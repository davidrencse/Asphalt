# What Does PacketIndex Do? (Simple Explanation)

## Think: **Book Index vs. Book Content**

- **Book Content** = The actual story (pages 1-300)
- **Book Index** = That section in the back that says:
  - "Elephants, mentioned on pages 45, 89, 156"
  - "Africa, discussed on pages 23-56"
  - "Zebra, page 102"

**PacketIndex is the "back of the book" for your PCAP file.**

## Real Example:

You have a PCAP file with 1,000,000 packets. You want to find:

> "Show me all packets between 2:00 PM and 2:01 PM"

**Without PacketIndex:**
- Read ALL 1,000,000 packets
- Check each timestamp
- Takes forever

**With PacketIndex:**
- Look in the "timestamp index" 
- Jump directly to packets around 2:00 PM
- Read maybe 1,000 packets
- Done in milliseconds

## What's Actually in the PacketIndex?

It's like a **library catalog card** for each packet:

```python
# For packet #42 in the file:
{
    "packet_id": 42,          # "Book #42 on shelf"
    "timestamp_us": 1700000000,  # "Published: 2023"
    "pcap_ref": "0:4200:4216",   # "Location: Shelf A, Row 3"
    "packet_hash": "abc123...",   # "ISBN number"
    "src_ip": "192.168.1.100",    # "Author: John"
    "dst_ip": "8.8.8.8",          # "Publisher: Google"
    "protocol": 6,                # "Genre: TCP"
    # ... other metadata
}
```

## The Key Fields Explained:

### 1. `pcap_ref` - The "GPS Coordinates"
```
"0:4200:4216"
 │   │    └── Data starts at byte 4216
 │   └─────── Packet record starts at byte 4200  
 └─────────── File ID #0 (first file in session)
```
**Why?** So we can JUMP directly to the packet without reading the whole file.

### 2. `packet_hash` - The "Fingerprint"
A unique ID for this exact packet. Like an ISBN for books.
- Same packet data → Same hash
- Different packet data → Different hash
- Used to detect duplicates

### 3. `timestamp_us` - The "When"
Microseconds since 1970. Allows:
- "Show packets from 2:00-2:01 PM"
- "Sort by time"
- "Find the first/last packet"

### 4. `src_ip`, `dst_ip`, `protocol` - The "Who & What"
(Placeholders in Sprint 0.2, will be filled later)
Allows queries like:
- "Show all traffic to 8.8.8.8"
- "Find HTTP packets (port 80)"
- "Show TCP connections"

## What PacketIndexBuilder Actually Does:

```python
# Input: RawPacket (the actual packet data)
packet = RawPacket(
    packet_id=1,
    timestamp_us=1700000000,
    data=b'\x00\x01\x02...',  # Actual packet bytes
    pcap_ref="0:100:116"
