# Sess manifest handling
"""
Session manifest creation and management.

The session manifest is the authoritative metadata source for a capture session.
Think of it as a "receipt" that documents everything about the capture:

1. WHAT was captured (source file, timestamps, packet count)
2. WHERE it's stored (file mappings for multi-file sessions)
3. HOW it was processed (schema versions for compatibility)
4. WHEN it was created (creation timestamp for freshness)

The manifest is:
- Deterministic: Same input → same manifest (critical!)
- Immutable: Once created, shouldn't change
- Portable: Can be moved with the data
- Self-describing: Contains all needed metadata
"""

import json
import hashlib
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from pathlib import Path
import os


@dataclass
class SessionManifest:
    """
    Authoritative metadata for a capture session.
    
    This is a DATA CONTAINER - no business logic here.
    Just stores and validates the metadata.
    
    Fields are designed for:
    1. Deterministic hashing (session_id = hash(source + time + count))
    2. Backward compatibility (default values, schema versions)
    3. Fast lookups (time range, file mappings)
    4. Debugging (original path, capture settings)
    """
    
    # ==================== CORE IDENTIFICATION ====================
    session_id: str
    """
    Deterministic hash of (source_hash + time_range + packet_count).
    
    Format: blake2b_hexdigest(32 bytes = 64 chars)
    Example: "e4d7f1b4c5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2"
    
    This is the PRIMARY KEY for the session.
    Same inputs → same session_id → deterministic!
    """
    
    created_at: str
    """
    When this manifest was created (UTC).
    
    Format: ISO 8601 with 'Z' suffix for UTC.
    Example: "2024-01-20T14:30:45.123456Z"
    
    Used for:
    - Knowing when analysis was done
    - Version comparisons
    - Cache invalidation
    """
    
    # ==================== SOURCE INFORMATION ====================
    source_type: str
    """
    How packets were acquired.
    
    Values: "file", "interface", "upload", "stream"
    
    Determines what other fields are relevant:
    - "file": source_hash, original_path, file_mapping
    - "interface": interface_name, capture_filter
    - "upload": source_hash only
    """
    
    source_hash: str
    """
    Cryptographic hash of the original data source.
    
    For files: SHA256 of the file bytes.
    For interfaces: Hash of (interface + start_time + filter).
    For uploads: SHA256 of uploaded data.
    
    Used for:
    - Data integrity verification
    - Duplicate detection
    - Deterministic session_id generation
    """
    
    # ==================== TEMPORAL SCOPE ====================
    time_start_us: int
    """
    Earliest packet timestamp in microseconds since Unix epoch.
    
    Example: 1700000000000000 (2023-11-14T22:13:20Z)
    
    Used for:
    - Time-based queries ("show packets after X")
    - Duration calculations
    - Timeline visualizations
    """
    
    time_end_us: int
    """
    Latest packet timestamp in microseconds.
    
    Must be >= time_start_us.
    
    Together with time_start_us defines the session's time window.
    """
    
    # ==================== PACKET STATISTICS ====================
    total_packets: int
    """
    Total packets in the session.
    
    Must be >= 0.
    Used for:
    - Progress tracking
    - Resource allocation
    - Statistical analysis
    """
    
    total_bytes_captured: int
    """
    Sum of captured_length for all packets.
    
    This is the actual bytes stored on disk.
    May be less than total_bytes_original due to snaplen.
    """
    
    total_bytes_original: int
    """
    Sum of original_length for all packets.
    
    This is the bytes that were on the wire.
    Used for bandwidth calculations.
    """
    
    # ==================== STORAGE MAPPING ====================
    file_mapping: Dict[str, str] = field(default_factory=dict)
    """
    Maps file_id to file path for multi-file sessions.
    
    Format: {"0": "/data/part1.pcap", "1": "/data/part2.pcap"}
    
    file_id is used in pcap_ref: "file_id:offset"
    Allows random access to packets across multiple files.
    """
    
    # ==================== SCHEMA VERSIONING ====================
    index_schema_version: str = "0.2.0"
    """
    Version of PacketIndexRecord schema used.
    
    Format: "MAJOR.MINOR.PATCH"
    
    Enables schema evolution:
    - Different versions can coexist
    - Migration scripts can detect old formats
    - Backward compatibility checks
    """
    
    manifest_schema_version: str = "0.2.0"
    """
    Version of THIS manifest schema.
    
    Allows the manifest format itself to evolve.
    When adding/removing fields, increment this.
    """
    
    # ==================== CAPTURE METADATA ====================
    capture_filter: Optional[str] = None
    """
    BPF filter applied during capture (if any).
    
    Example: "tcp port 80 or port 443"
    
    Important for understanding what might be missing.
    """
    
    interface_name: Optional[str] = None
    """
    Network interface name for live captures.
    
    Example: "eth0", "en0", "Wi-Fi"
    """
    
    link_types: List[int] = field(default_factory=list)
    """
    List of DLT_* link types present in the session.
    
    Example: [1] for Ethernet, [1, 12] for mixed Ethernet/RawIP.
    
    Used for:
    - Protocol decoder selection
    - Format validation
    - Statistics
    """
    
    snaplen: Optional[int] = None
    """
    Maximum captured packet length (if limited).
    
    None means no limit (full packets captured).
