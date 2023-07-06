#!/usr/bin/env python
"""
Asphalt launcher - use this as your CLI.
"""
import sys
import os

# Add src to path
current_dir = os.path.dirname(os.path.abspath(__file__))
src_path = os.path.join(current_dir, 'src')
sys.path.insert(0, src_path)

# Import and run
from asphalt_cli.capture import capture
