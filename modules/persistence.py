import sys
import platform
from pathlib import Path
from typing import Dict, Any
import logging

sys.path.append(str(Path(__file__).resolve().parent.parent))

from modules.base_module import BaseSimulationModule  # pyre-ignore
from utils.logger import log_info, log_error, log_event  # pyre-ignore
from utils.safe_executor import simulate_command, simulate_artifact_creation  # pyre-ignore


class PersistenceModule(BaseSimulationModule):
    """T1053/T1547 - Simulates scheduled tasks, registry run keys, startup folder; no real OS changes."""
    def __init__(self):
        BaseSimulationModule.__init__(self, technique_name="T1053, T1547", base_risk_score=30)

    def execute(self, context: Dict[str, Any], logger: logging.Logger, live_callback=None) -> None:
        log_info(logger=logger, message="T1053/T1547 Persistence simulation.",
                 scenario=context.get("scenario_name", "Unknown"), module="persistence",
                 action="Footprint Establishment", mitre=self.technique, details="Log-only.")
        try:
            methods = []
            is_win = platform.system() == "Windows"
            if live_callback: live_callback("Creating scheduled task (T1053)...")
            if is_win:
                simulate_command("schtasks /create /sc ONSTART /tn 'SimulatedUpdater' /tr 'C:\\Windows\\Temp\\mock.exe'")
                methods.append("scheduled_task")
                if live_callback: live_callback("Adding registry Run key (T1547.001)...")
                simulate_command("reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Update /d mock.exe /f")
                methods.append("registry_run_key")
            else:
                simulate_command('(crontab -l 2>/dev/null; echo "@reboot /tmp/mock.sh") | crontab -')
                methods.append("crontab")
                simulate_command("echo '/tmp/mock.sh' >> ~/.bashrc")
                methods.append("bashrc_autorun")
            if live_callback: live_callback("Dropping startup folder payload...")
            simulate_artifact_creation("Mock_Startup.bat" if is_win else "Mock_Startup.sh",
                                       "@echo off\nREM RedSim persistence marker" if is_win else "#!/bin/bash\n# RedSim persistence marker")
            methods.append("startup_folder")
            self.metadata = {"module": "persistence", "status": "success", "methods": methods}
            self.risk_score += len(methods) * 15
            self.status_msg = f"Persistence via {len(methods)} mechanisms: {', '.join(methods)}."
            log_event(scenario=context.get("scenario_name", "N/A"), module="persistence",
                      action="Persistence achieved", status="success",
                      mitre_technique=self.technique, details=self.status_msg)
        except Exception as e:
            self.metadata = {"module": "persistence", "status": "failed", "methods": []}
            self.risk_score = 0; self.status_msg = str(e)

    def run(self, context, logger, live_callback=None):
        r = super().run(context, logger, live_callback); r.update(self.metadata); return r

def run(context, logger, live_callback=None):
    return PersistenceModule().run(context, logger, live_callback)
