# ==========================================
# RedSim – Adversary Simulation Platform
# Modules Package Initializer
# ==========================================

from pathlib import Path
from typing import List

def get_available_modules() -> List[str]:
    """
    Dynamically scans the generic `modules/` package recursively 
    and returns a formatted list of strictly importable payload routes.
    
    Example output item format: 'discovery.mock_discovery'
    """
    available_targets = []
    base_dir = Path(__file__).resolve().parent
    
    # Recursively seek python files matching payload constraints
    for py_file in base_dir.rglob("*.py"):
        
        # Omit structural platform scripts instead of simulation payloads
        if py_file.name in ("__init__.py", "base_module.py"):
            continue
            
        # Prevent parsing compiled binaries natively
        if "__pycache__" in py_file.parts:
            continue
            
        # Translate the relative file path like 'discovery/mock_discovery.py'
        # into the strict python package nomenclature 'discovery.mock_discovery'
        rel_path = py_file.relative_to(base_dir)
        module_route = str(rel_path.with_suffix('')).replace("\\", ".").replace("/", ".")
        
        available_targets.append(module_route)
        
    return sorted(available_targets)

# Export a static list configuration automatically populated during package loading
AVAILABLE_MODULES = get_available_modules()

# Make the utility available when checking `from modules import get_available_modules`
__all__ = ["AVAILABLE_MODULES", "get_available_modules"]
