import sys
import platform
from pathlib import Path
from typing import Dict, Any
import logging
from datetime import datetime

sys.path.append(str(Path(__file__).resolve().parent.parent))

from config import LAB_SETTINGS  # pyre-ignore
from utils.safe_executor import simulate_network_action, simulate_artifact_creation  # pyre-ignore
from modules.base_module import BaseSimulationModule  # pyre-ignore
from utils.logger import log_info, log_error  # pyre-ignore
from utils.mitre_mapper import get_mitre_mapping  # pyre-ignore


class LateralMovementModule(BaseSimulationModule):
    """T1021/T1570 - Simulates SMB share enumeration and tool transfer; no real sockets opened."""
    def __init__(self):
        BaseSimulationModule.__init__(self, technique_name="T1021", base_risk_score=20)
        self.mapping = get_mitre_mapping("lateral_movement")

    def execute(self, context: Dict[str, Any], logger: logging.Logger, live_callback=None) -> None:
        log_info(logger=logger, message="T1021/T1570 Lateral Movement simulation.",
                 scenario=context.get("scenario_name", "Unknown"), module="lateral_movement",
                 action="SMB Enumeration", mitre=self.technique, details="Log-only, no sockets.")
        try:
            target = LAB_SETTINGS.get("victim_host", "192.168.1.101")
            is_win = platform.system() == "Windows"
            if live_callback: live_callback(f"Enumerating ports on {target}...")
            for port in ([139, 445, 3389, 5985] if is_win else [22, 2049, 5900]):
                simulate_network_action(f"SYN {target}:{port}")
            shares = ["IPC$", "C$", "ADMIN$"] if is_win else ["/var/nfs", "/backup"]
            if live_callback: live_callback(f"Found {len(shares)} shares; dropping tool...")
            payload = f"smb_dropper_{int(datetime.now().timestamp())}.txt"
            simulate_artifact_creation(payload, "MOCK LATERAL MOVEMENT DROPPER (BENIGN)")
            self.metadata = {"module": "lateral_movement", "status": "success",
                             "target": target, "shares": shares, "payload": payload}
            context["lateral_nodes_compromised"] = 1
            self.risk_score += len(shares) * 10 + 25
            self.status_msg = f"Lateral hop to {target}: {len(shares)} shares, dropper staged."
        except Exception as e:
            self.metadata = {"module": "lateral_movement", "status": "failed",
                             "target": "", "shares": [], "payload": ""}
            self.risk_score = 0; self.status_msg = str(e)

    def run(self, context, logger, live_callback=None):
        r = super().run(context, logger, live_callback); r.update(self.metadata); return r

def run(context, logger, live_callback=None):
    return LateralMovementModule().run(context, logger, live_callback)
