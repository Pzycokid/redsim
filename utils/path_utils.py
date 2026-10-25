import os, sys

def get_base_dir() -> str:
    """Returns the directory containing the script or executable."""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
