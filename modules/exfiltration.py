import os
import sys
import shutil
from pathlib import Path
from typing import Dict, Any
import logging
from datetime import datetime

sys.path.append(str(Path(__file__).resolve().parent.parent))

from config import LAB_DIR, REPORT_DIR  # pyre-ignore
from utils.logger import log_info, log_error, log_event  # pyre-ignore
from utils.helpers import ensure_directory  # pyre-ignore
from modules.base_module import BaseSimulationModule  # pyre-ignore


class ExfiltrationModule(BaseSimulationModule):
    """T1041/T1567 - Packages lab dummy data into a zip; no external network calls."""
    def __init__(self):
        BaseSimulationModule.__init__(self, technique_name="T1041, T1567", base_risk_score=50)

    def execute(self, context: Dict[str, Any], logger: logging.Logger, live_callback=None) -> None:
        log_info(logger=logger, message="T1041/T1567 Exfiltration simulation.",
                 scenario=context.get("scenario_name", "Unknown"), module="exfiltration",
                 action="Data Staging", mitre=self.technique, details="Offline zip only.")
        try:
            if live_callback: live_callback("Preparing exfiltration sandbox...")
            sample_dir = ensure_directory(LAB_DIR / "sample_data")
            staging_dir = ensure_directory(REPORT_DIR / "staging")
            targets = [f for f in sample_dir.rglob("*") if f.is_file()]
            if not targets:
                dummy = sample_dir / "mock_data.txt"
                dummy.write_text("RedSim mock exfiltration payload.\n")
                targets = [dummy]
            if live_callback: live_callback(f"Staging {len(targets)} file(s) for exfiltration...")
            archive_name = str(staging_dir / f"egress_{datetime.now().strftime('%Y%m%d%H%M%S')}")
            zipped = shutil.make_archive(archive_name, 'zip', str(sample_dir))
            if live_callback: live_callback(f"Archive created: {Path(zipped).name}")
            self.metadata = {"module": "exfiltration", "status": "success",
                             "files_collected": len(targets), "archive": Path(zipped).name}
            self.risk_score += len(targets) * 5
            self.status_msg = f"Packaged {len(targets)} files into {Path(zipped).name}."
            log_event(scenario=context.get("scenario_name", "N/A"), module="exfiltration",
                      action="Archive staged", status="success",
                      mitre_technique=self.technique, details=self.status_msg)
        except Exception as e:
            self.metadata = {"module": "exfiltration", "status": "failed",
                             "files_collected": 0, "archive": ""}
            self.risk_score = 0; self.status_msg = str(e)

    def run(self, context, logger, live_callback=None):
        r = super().run(context, logger, live_callback); r.update(self.metadata); return r

def run(context, logger, live_callback=None):
    return ExfiltrationModule().run(context, logger, live_callback)
