# PACKET CAPTURE SYSTEM

The packet capture system is FULLY WORKING! You've successfully captured real network packets from Wi-Fi interface

```bash
PS C:\Users\david\Desktop\all projects\Cybersecurity\Asphalt> asphalt capture --interface list
Available interfaces:

=== Dummy Interfaces (for testing) ===
  dummy0               Dummy Ethernet Interface
  dummy1               Dummy Wi-Fi Interface

No real interfaces found.
Note: Interface names are GUIDs like \Device\NPF_{...}
      Use the exact name shown above for capture.
PS C:\Users\david\Desktop\all projects\Cybersecurity\Asphalt> asphalt capture --interface "Wi-Fi" --duration 10 --backend scapy
DEBUG: Starting capture with interface: 'Wi-Fi'
DEBUG: Filter: 'None'
DEBUG: Promisc: True
DEBUG: Mapped 'Wi-Fi' -> '\Device\NPF_{2E9DED45-5239-4F79-BA74-71F082736A21}'
DEBUG: Description: Intel(R) Wi-Fi 6 AX201 160MHz
DEBUG: Creating AsyncSniffer with interface='\Device\NPF_{2E9DED45-5239-4F79-BA74-71F082736A21}'
DEBUG: Starting sniffer...
DEBUG: Sniffer started successfully
DEBUG: Capture session scapy_1768831934_4910871183864461286 started successfully
Capture started on 'Wi-Fi' (session: scapy_1768831934_4910871183864461286)
Duration: 10 seconds
Press Ctrl+C to stop

Time   Pkts/s   Total      Drops
----------------------------------------
DEBUG: Captured packet 1: 60 bytes
DEBUG: Captured packet 2: 380 bytes
DEBUG: Captured packet 3: 60 bytes
DEBUG: Captured packet 4: 195 bytes
  9.6s       23        122        0
Duration reached (10s), stopping...

==================================================
CAPTURE SUMMARY
==================================================
Session ID:    scapy_1768831934_4910871183864461286
Interface:     Wi-Fi
Duration:      10.55s
Total Packets: 164
Total Bytes:   43,494
Packet Drops:  0
PS C:\Users\david\Desktop\all projects\Cybersecurity\Asphalt> asphalt capture --interface "\Device\NPF_{B517604C-6715-44B9-A8E1-19BC3A8AA3DC}" --duration 5
Capture started on '\Device\NPF_{B517604C-6715-44B9-A8E1-19BC3A8AA3DC}' (session: dummy_1768831947)
Duration: 5 seconds
Press Ctrl+C to stop

Time   Pkts/s   Total      Drops   
----------------------------------------
  4.8s       64        272        0
Duration reached (5s), stopping...

==================================================
CAPTURE SUMMARY
==================================================
Session ID:    dummy_1768831947
