"""
Capture backend interface definition.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, Dict, Any, List

@dataclass
class CaptureConfig:
    """Capture configuration."""
    interface: str
    snaplen: int = 65535
    promisc: bool = True
    timeout_ms: int = 1000
    buffer_size: int = 10000  # Queue size
    filter: Optional[str] = None
    monitor: bool = False  # Monitor mode for WiFi

class ICaptureBackend(ABC):
    """Capture backend interface."""
    
    @abstractmethod
    def start(self, config: CaptureConfig) -> str:
        """Start capture, return session_id."""
        pass
