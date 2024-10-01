import sys
import os

# Add src to path
current_dir = os.path.dirname(os.path.abspath(__file__))
src_path = os.path.join(current_dir, 'src')
sys.path.insert(0, src_path)

print("Testing ScapyBackend...")
print("=" * 60)

# Test 1: Can we import Scapy?
try:
    import scapy
    print("✅ Scapy imported successfully")
    print(f"   Scapy path: {scapy.__file__}")
