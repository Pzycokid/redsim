import os
import sys
from pathlib import Path
from typing import Dict, Any
import logging

sys.path.append(str(Path(__file__).resolve().parent.parent))

from config import LAB_DIR  # pyre-ignore
from utils.helpers import ensure_directory, save_json_file, load_json_file  # pyre-ignore
from modules.base_module import BaseSimulationModule  # pyre-ignore
from utils.logger import log_info, log_error, log_event  # pyre-ignore

class CredentialAccessModule(BaseSimulationModule):
    """T1110 - Brute Force: iterates a proxy dictionary against lab dummy accounts only."""
    def __init__(self):
        BaseSimulationModule.__init__(self, technique_name="T1110", base_risk_score=35)

    def _setup_dummy_data(self):
        sample_dir = ensure_directory(LAB_DIR / "sample_data")
        dummy_file = sample_dir / "dummy_users.json"
        if not dummy_file.exists():
            data = [
                {"username": "admin", "password_hint": "Password1", "weak": True},
                {"username": "svc_backup", "password_hint": "admin", "weak": True},
                {"username": "user1", "password_hint": "changeme", "weak": True},
                {"username": "ceo", "password_hint": "S3cur3!C0mplex99", "weak": False}
            ]
            save_json_file(dummy_file, data)
        return dummy_file

    def execute(self, context: Dict[str, Any], logger: logging.Logger, live_callback=None) -> None:
        log_info(logger=logger, message="Initializing T1110 Password Spray simulation.",
                 scenario=context.get("scenario_name", "Unknown"), module="credential_access",
                 action="Password Spray", mitre=self.technique, details="Lab dict only.")
        try:
            if live_callback: live_callback("Staging credential vault...")
            accounts = load_json_file(self._setup_dummy_data())
            spray = ["admin", "Password1", "changeme", "qwerty", "12345"]
            attempts = 0; hits = 0; alerts = []
            for account in accounts:
                user = account.get("username", "unknown")
                for attempt in spray:
                    attempts += 1
                    alerts.append(f"Auth: USER '{user}' KEY '{attempt}'")
                    if attempt == account.get("password_hint") and account.get("weak"):
                        hits += 1
                        log_event(scenario=context.get("scenario_name", "N/A"), module="credential_access",
                                  action="Weak credential found", status="success",
                                  mitre_technique=self.technique, details=f"User: {user}")
                        break
            self.metadata = {"module": "credential_access", "status": "success",
                             "attempts": attempts, "weak_accounts_found": hits}
            context["lab_cracked_admin_count"] = hits
            self.risk_score += hits * 15
            self.status_msg = f"Sprayed {attempts} attempts; found {hits} weak accounts."
        except Exception as e:
            self.metadata = {"module": "credential_access", "status": "failed", "attempts": 0, "weak_accounts_found": 0}
            self.risk_score = 0; self.status_msg = str(e)

    def run(self, context, logger, live_callback=None):
        r = super().run(context, logger, live_callback); r.update(self.metadata); return r

def run(context, logger, live_callback=None):
    return CredentialAccessModule().run(context, logger, live_callback)
