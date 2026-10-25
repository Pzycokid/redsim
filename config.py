import os
import logging
from pathlib import Path

# ==========================================
# RedSim – Adversary Simulation Platform
# Central Configuration File
# ==========================================

# Core Safety Flag - Enforces benign lab execution only
SAFE_MODE = True

# ------------------------------------------
# Path Definitions
# ------------------------------------------
# Base directory of the project
BASE_DIR = Path(__file__).resolve().parent

# Required directories for application functioning
LOG_DIR = BASE_DIR / "logs"
REPORT_DIR = BASE_DIR / "reports"
SCENARIO_DIR = BASE_DIR / "scenarios"
LAB_DIR = BASE_DIR / "lab"
DASHBOARD_DIR = BASE_DIR / "web_dashboard"
MODULE_DIR = BASE_DIR / "modules"
UTILS_DIR = BASE_DIR / "utils"
DOCS_DIR = BASE_DIR / "docs"

# ------------------------------------------
# Simulation Boundaries & Reporting
# ------------------------------------------
# Supported file outputs for simulation runs
REPORT_FORMATS = ["json", "html", "pdf"]

# Standardized MITRE-based or custom risk scoring
RISK_THRESHOLDS = {
    "low": 30,
    "medium": 60,
    "high": 90,
    "critical": 100
}

# ------------------------------------------
# Default Lab Network Mappings
# ------------------------------------------
# Mocked or targeted IP addresses for simulated actions
LAB_SETTINGS = {
    "attacker_host": "192.168.56.20",
    "victim_host": "192.168.1.101",
    "server_host": "192.168.56.30"
}

# ------------------------------------------
# Helper Functions
# ------------------------------------------
def setup_environment():
    """
    Validates and creates essential directory structures for the simulator
    if they do not already exist. Keeps the project structure deterministic.
    """
    directories = [
        LOG_DIR, 
        REPORT_DIR, 
        SCENARIO_DIR, 
        LAB_DIR, 
        DASHBOARD_DIR,
        MODULE_DIR,
        UTILS_DIR,
        DOCS_DIR
    ]
    
    for directory in directories:
        try:
            if not directory.exists():
                directory.mkdir(parents=True, exist_ok=True)
                # Print is fine here as it runs before logger init
                print(f"[INIT] Created missing directory: {directory}")
        except PermissionError as e:
            print(f"[ERROR] Permission denied creating {directory}: {e}")
        except Exception as e:
            print(f"[ERROR] Auto-directory creation failed for {directory}: {e}")

if __name__ == "__main__":
    setup_environment()
    print("[INFO] RedSim environment checked successfully.")
