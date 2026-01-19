#!/usr/bin/env python
"""
Run Asphalt from project root.
"""
import sys
import os

# Get project root
project_root = os.path.dirname(os.path.abspath(__file__))
src_path = os.path.join(project_root, 'src')

# Add to path
if src_path not in sys.path:
    sys.path.insert(0, src_path)

# Now imports will work
try:
    from cli.main import cli
except ImportError as e:
    print(f"Error: {e}")
    print(f"Python path: {sys.path}")
    print(f"Looking for cli.main in: {src_path}")
    sys.exit(1)

if __name__ == "__main__":
    cli()