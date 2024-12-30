# Daily Recap: 2026-01-19

### **PacketIndexBuilder**
**What it does**: Creates searchable index cards for every packet
**Key learning**: 
- **Determinism is critical** - same input must always produce same output
- Uses **Blake2b hashing** for packet fingerprints (fast and cryptographic)
- Creates **pcap_ref** strings that work like "GPS coordinates" for packets: `"file_id:start_offset:data_offset"`
- Packet IDs must start at **1** and be monotonic (1, 2, 3...)


### **Models vs Interfaces**
- **Models** (`RawPacket`, `PacketIndexRecord`, `SessionManifest`) are **data containers**
- **Interfaces** (`IPacketSource`) are **contracts/job descriptions**
- Models **store data**, Interfaces **define what must be done** with data
- This separation prevents spaghetti code and enforces boundaries

- Models = **Pizza boxes** (hold data)
- Interfaces = **Pizza recipes** (define how to make them)
