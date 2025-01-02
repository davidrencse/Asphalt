# Asphalt Models Explained

## What Are Models?

Models are **data containers** - they define the **shape and rules** for data that flows through Asphalt. Think of them as **custom data types** that everyone agrees to use.

## Simple Analogy: Shipping Boxes

Imagine you run a warehouse:

- **Without models**: Workers throw items randomly into any box. "Is this a large or small item? Fragile or durable?" Nobody knows.
- **With models**: You have labeled boxes:
  - `SmallBox(max_weight=5kg, label="FRAGILE")`
  - `LargeBox(max_weight=20kg, label="DURABLE")`
  - Every worker knows exactly what goes where.

Models are those **labeled boxes**.

## The Three Core Models

### 1. `RawPacket` - The Raw Data Container

**What it does**: Stores exactly what comes out of a PCAP file.

```python
# Think of this as a "PCAP packet box"
@dataclass(frozen=True)  # Frozen = cannot be changed (important!)
class RawPacket:
    # REQUIRED LABELS on the box:
    packet_id: int          # "Box #1, #2, #3..."
    timestamp_us: int       # "Created at: 1,234,567,890 microseconds"
    captured_length: int    # "Actual contents: 64 bytes"
    original_length: int    # "Original size: 64 bytes"  
    link_type: int          # "Contents type: Ethernet"
    data: bytes             # THE ACTUAL DATA inside
    pcap_ref: str           # "Location: file 0, starts at byte 100"
    
    # OPTIONAL labels:
    interface_id: Optional[int] = None  # "From camera #2"
    comment: Optional[str] = None       # "Note: suspicious"
```

**Why frozen?** So nobody can change a packet after it's created. If you need to modify it, you create a NEW packet.

### 2. `PacketIndexRecord` - The Search Index Entry

**What it does**: Creates a "library card" for each packet so we can find it later.

```python
# Think of this as a "library catalog card"
@dataclass
class PacketIndexRecord:
    # BASIC INFO (like book title/author)
    packet_id: int          # "Book #42 in this library"
    session_id: str         # "Library: Downtown Branch"
    timestamp_us: int       # "Published: 1998"
