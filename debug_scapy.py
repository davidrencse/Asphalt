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
except ImportError as e:
    print(f"❌ Scapy import failed: {e}")
    sys.exit(1)

# Test 2: Can Scapy find interfaces directly?
try:
    from scapy.all import get_if_list
    print("\n✅ Scapy.get_if_list() imported")
