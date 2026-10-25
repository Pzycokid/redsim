import time
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

sys.path.append(str(Path(__file__).resolve().parent.parent))
from config import LAB_DIR  # pyre-ignore

# ==========================================
# RedSim - Safe Execution Primitives
# ALL system calls are simulated — no shell, no sockets, no real FS changes
# ==========================================

def _build_status(action_type: str, message: str, status: str = "success") -> dict:
    return {"action": action_type, "status": status, "message": message,
            "timestamp": datetime.now().isoformat()}

def _log(): return logging.getLogger("RedSim-Controller")

def simulate_command(command_description: str) -> dict:
    """Logs the command string — calls no shell (no subprocess/os.system)."""
    msg = f"Simulated OS Command: '{command_description}'"
    _log().info(msg)
    return _build_status("shell_command", msg)

def simulate_file_operation(action: str, src: Optional[str] = None, dst: Optional[str] = None) -> dict:
    """Logs a file action — modifies no OS files."""
    msg = f"Simulated File [{action.upper()}]"
    if src: msg += f" from: {src}"
    if dst: msg += f" to: {dst}"
    _log().info(msg)
    return _build_status("file_operation", msg)

def simulate_network_action(description: str) -> dict:
    """Logs a network event — opens no sockets."""
    msg = f"Simulated Network: {description}"
    _log().info(msg)
    return _build_status("network_action", msg)

def simulate_delay(seconds: float) -> dict:
    """Actual sleep to mimic APT timing behaviour."""
    _log().info(f"Sleeping {seconds}s (APT timing simulation)")
    time.sleep(float(seconds))
    return _build_status("execution_delay", f"Slept {seconds}s.")

def simulate_artifact_creation(path: str, content: str) -> dict:
    """Writes only inside the lab/ sandbox — path-traversal stripped."""
    try:
        safe_name = Path(path).name          # strip any ../
        jailed = LAB_DIR / safe_name
        with open(jailed, 'w', encoding='utf-8') as f:
            f.write(content)
        msg = f"Artifact planted at: {jailed}"
        _log().info(msg)
        return _build_status("artifact_creation", msg)
    except Exception as e:
        msg = f"Artifact creation failed: {e}"
        _log().error(msg)
        return _build_status("artifact_creation", msg, status="failure")
