import shutil
import sys
from typing import Dict, Any
import logging
from datetime import datetime
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from config import LAB_DIR  # pyre-ignore
from utils.logger import log_info, log_error, log_event  # pyre-ignore
from utils.helpers import ensure_directory  # pyre-ignore
from modules.base_module import BaseSimulationModule  # pyre-ignore


class RansomwareSimModule(BaseSimulationModule):
    """T1486 - Copies dummy files with .locked extension in sandbox only; no AES/real encryption."""
    def __init__(self):
        BaseSimulationModule.__init__(self, technique_name="T1486", base_risk_score=75)

    def execute(self, context: Dict[str, Any], logger: logging.Logger, live_callback=None) -> None:
        log_info(logger=logger, message="T1486 Ransomware simulation.",
                 scenario=context.get("scenario_name", "Unknown"), module="ransomware_sim",
                 action="Encryption Simulation", mitre=self.technique, details="Sandbox copy only.")
        try:
            sample_dir = ensure_directory(LAB_DIR / "sample_data")
            sandbox = ensure_directory(LAB_DIR / f"ransomware_sandbox_{int(datetime.now().timestamp())}")
            targets = [f for f in sample_dir.rglob("*") if f.is_file()]
            if not targets:
                if live_callback: live_callback("Seeding dummy financial data...")
                dummy = sample_dir / "mock_financials.csv"
                dummy.write_text("Account,Balance\nCEO,500000\nSVC,0\n")
                targets = [dummy]
            if live_callback: live_callback(f"Simulating .locked extension on {len(targets)} file(s)...")
            for f in targets:
                shutil.copy2(f, sandbox / f"{f.name}.locked")
            (sandbox / "RANSOM_NOTE.txt").write_text(
                "[REDSIM SIMULATION]\nNo real files were encrypted.\n"
                "This is a safe SOC detection test."
            )
            if live_callback: live_callback("Ransom note dropped.")
            self.metadata = {"module": "ransomware_sim", "status": "success",
                             "files_locked": len(targets), "sandbox": str(sandbox)}
            self.risk_score += len(targets) * 20
            self.status_msg = f"Simulated encrypting {len(targets)} files in {sandbox.name}."
            log_event(scenario=context.get("scenario_name", "N/A"), module="ransomware_sim",
                      action="Sandbox encryption complete", status="success",
                      mitre_technique=self.technique, details=self.status_msg)
        except Exception as e:
            self.metadata = {"module": "ransomware_sim", "status": "failed",
                             "files_locked": 0, "sandbox": ""}
            self.risk_score = 0; self.status_msg = str(e)

    def run(self, context, logger, live_callback=None):
        r = super().run(context, logger, live_callback); r.update(self.metadata); return r

def run(context, logger, live_callback=None):
    return RansomwareSimModule().run(context, logger, live_callback)
