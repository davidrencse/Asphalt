#!/usr/bin/env python
"""
Run Asphalt from project root.
"""
import sys
import os

# Get project root
project_root = os.path.dirname(os.path.abspath(__file__))
src_path = os.path.join(project_root, 'src')

# Add to path (ensure src precedes project root to avoid name shadowing)
if src_path not in sys.path:
    sys.path.insert(0, src_path)
# Remove project root from sys.path to prevent asphalt_cli.py shadowing package
if project_root in sys.path:
    sys.path = [p for p in sys.path if p != project_root]
    sys.path.insert(1, project_root)

# Now imports will work
try:
    if 'asphalt_cli' in sys.modules:
        del sys.modules['asphalt_cli']
    from asphalt_cli.main import cli
except ImportError as e:
    print(f"Error: {e}")
    print(f"Python path: {sys.path}")
    print(f"Looking for cli.main in: {src_path}")
    sys.exit(1)

if __name__ == "__main__":
    cli()
