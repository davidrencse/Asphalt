# debug_imports.py
import os
import sys

current_dir = os.path.dirname(os.path.abspath(__file__))
src_path = os.path.join(current_dir, 'src')
capture_dir = os.path.join(src_path, 'capture')

print(f"Checking files in: {capture_dir}")
print("=" * 50)

for filename in ['icapture_backend.py', 'scapy_backend.py', 'dummy_backend.py', 'live_source.py']:
    filepath = os.path.join(capture_dir, filename)
    print(f"\n{filename}:")
    print("-" * 30)
    if os.path.exists(filepath):
        with open(filepath, 'r') as f:
            # Read first 20 lines to see imports
            for i in range(20):
                line = f.readline()
                if not line:
                    break
                if 'import' in line or 'from' in line:
                    print(f"  Line {i+1}: {line.rstrip()}")
    else:
        print(f"  File not found!")