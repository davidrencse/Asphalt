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
- Implementations = **Pizza chefs** (actually make the pizza)

### **@abstractmethod**
- `@abstractmethod` means "child classes MUST implement this"
- Interface files only contain `pass` for abstract methods
- Concrete implementations go in separate files (`pcap_reader.py`)
- Context manager methods (`__enter__`, `__exit__`, `__del__`) can be implemented in the interface because they're always the same


### **PCAP File Structure **
PCAP files have:
- **24-byte global header** with magic number, version, link type
- **Magic numbers** determine endianness and timestamp resolution
- Each packet has: **16-byte header** (timestamp + lengths) + **packet data**
- **Padding** to 32-bit boundaries (important for file navigation)
