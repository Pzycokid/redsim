import base64
import sys
import platform
from pathlib import Path
from typing import Dict, Any
import logging

sys.path.append(str(Path(__file__).resolve().parent.parent))

from utils.logger import log_info, log_error, log_event  # pyre-ignore
from utils.safe_executor import simulate_delay, simulate_file_operation, simulate_command  # pyre-ignore
from modules.base_module import BaseSimulationModule  # pyre-ignore


class DefenseEvasionModule(BaseSimulationModule):
    """T1218/T1027 - Generates EDR-flagged strings (encoded PS, LOLBins, masquerading) in logs only."""
    def __init__(self):
        BaseSimulationModule.__init__(self, technique_name="T1218, T1027", base_risk_score=45)

    def execute(self, context: Dict[str, Any], logger: logging.Logger, live_callback=None) -> None:
        if live_callback: live_callback("Initializing EDR evasion simulation...")
        log_info(logger=logger, message="T1218/T1027 Defense Evasion simulation.",
                 scenario=context.get("scenario_name", "Unknown"), module="defense_evasion",
                 action="Obfuscation", mitre=self.technique, details="Log-only, no shell execution.")
        try:
            events = []
            simulate_delay(1.0); events.append("sandbox_delay_1s")
            is_win = platform.system() == "Windows"
            if live_callback: live_callback("Simulating log clearing (T1070.001)...")
            simulate_command("wevtutil cl Security" if is_win else "cat /dev/null > /var/log/syslog")
            events.append("log_clear")
            if live_callback: live_callback("Simulating file masquerading (T1036)...")
            simulate_file_operation(action="masquerade_rename",
                src="RedSimDropper.exe" if is_win else "RedSimDropper.sh",
                dst="svchost.exe" if is_win else "systemd-update")
            events.append("masquerade_rename")
            if live_callback: live_callback("Generating encoded command (T1027)...")
            encoded = base64.b64encode(b"echo safe mock").decode()
            simulate_command(f"powershell -EncodedCommand {encoded}" if is_win else f"echo {encoded} | base64 -d | sh")
            events.append("encoded_command")
            if live_callback: live_callback("Simulating LOLBin execution (T1218)...")
            simulate_command("rundll32.exe javascript:\"..\\mshtml,RunHTMLApplication\"" if is_win else "awk 'BEGIN {system(\"echo mock\")}'")
            events.append("lolbin")
            self.metadata = {"module": "defense_evasion", "status": "success", "evasion_events": events}
            self.risk_score += len(events) * 15
            self.status_msg = f"{len(events)} evasion techniques simulated."
            log_event(scenario=context.get("scenario_name", "N/A"), module="defense_evasion",
                      action="Evasion traces deployed", status="success",
                      mitre_technique=self.technique, details=self.status_msg)
        except Exception as e:
            self.metadata = {"module": "defense_evasion", "status": "failed", "evasion_events": []}
            self.risk_score = 0; self.status_msg = str(e)

    def run(self, context, logger, live_callback=None):
        r = super().run(context, logger, live_callback); r.update(self.metadata); return r

def run(context, logger, live_callback=None):
    return DefenseEvasionModule().run(context, logger, live_callback)
