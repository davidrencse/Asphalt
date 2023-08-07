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
sys.path = [p for p in sys.path if p != src_path]
sys.path.insert(0, src_path)
