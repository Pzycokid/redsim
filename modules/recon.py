import sys
import platform
import psutil  # pyre-ignore
import logging
from pathlib import Path
from typing import Dict, Any

sys.path.append(str(Path(__file__).resolve().parent.parent))

from modules.base_module import BaseSimulationModule  # pyre-ignore
from utils.logger import log_info, log_error  # pyre-ignore
from utils.mitre_mapper import get_mitre_mapping  # pyre-ignore


class ReconModule(BaseSimulationModule):
    """T1082 - System Information Discovery using local OS properties; no active scanning."""
    def __init__(self):
        BaseSimulationModule.__init__(self, technique_name="T1082", base_risk_score=15)
        self.mapping = get_mitre_mapping("recon")

    def execute(self, context: Dict[str, Any], logger: logging.Logger, live_callback=None) -> None:
        if live_callback: live_callback("Identifying host architecture...")
        log_info(logger=logger, message="T1082 System Discovery.",
                 scenario=context.get("scenario_name", "Unknown"), module="recon",
                 action="Enumeration", mitre=self.technique, details="Local OS properties only.")
        try:
            from config import LAB_SETTINGS  # pyre-ignore
            target = LAB_SETTINGS.get("victim_host", "192.168.1.101")
            hostname = f"VICTIM-{target.split('.')[-1]}"
            os_name = "Windows" if platform.system() == "Windows" else "Linux"
            if live_callback: live_callback(f"Target: {hostname} ({os_name})")
            proc_count = len(psutil.pids())
            if live_callback: live_callback(f"Process count: {proc_count}")
            self.metadata = {
                "module": "recon", "status": "success",
                "hostname": hostname, "os": os_name,
                "ip": target, "process_count": proc_count
            }
            context.update(self.metadata)
            self.status_msg = f"Recon: {hostname} ({os_name}), {proc_count} processes."
        except Exception as e:
            self.metadata = {
                "module": "recon", "status": "failed",
                "hostname": "Unknown", "os": "Unknown",
                "ip": "Unknown", "process_count": 0
            }
            self.risk_score = 0; self.status_msg = str(e)

    def run(self, context, logger, live_callback=None):
        r = super().run(context, logger, live_callback); r.update(self.metadata); return r

def run(context, logger, live_callback=None):
    return ReconModule().run(context, logger, live_callback)
