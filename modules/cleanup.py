import shutil,sys
from pathlib import Path
from typing import Dict,Any
import logging
sys.path.append(str(Path(__file__).resolve().parent.parent))
from config import LAB_DIR,REPORT_DIR
from utils.logger import log_info,log_error,log_event
from modules.base_module import BaseSimulationModule

class CleanupModule(BaseSimulationModule):
    """T1070.004 - Indicator Removal: safely wipes RedSim lab artifacts after a run."""
    def __init__(self): BaseSimulationModule.__init__(self,'T1070.004',10)
    def execute(self,context,logger,live_callback=None):
        actions=[]
        for sd in LAB_DIR.glob('ransomware_sandbox_*'):
            shutil.rmtree(sd,ignore_errors=True); actions.append(f'Removed {sd.name}')
        staging=REPORT_DIR/'staging'
        if staging.exists():
            for z in staging.glob('simulated_e*.zip'): z.unlink(missing_ok=True); actions.append(f'Removed {z.name}')
        for d in LAB_DIR.glob('smb_dropper_*.txt'): d.unlink(missing_ok=True); actions.append(f'Removed {d.name}')
        self.metadata={'module':'cleanup','status':'completed','actions':actions}
        self.risk_score+=len(actions)*5
        self.status_msg=f'Cleaned {len(actions)} artifacts.'
        log_event(scenario=context.get('scenario_name','N/A'),module='cleanup',action='Artifacts removed',status='success',mitre_technique=self.technique,details=self.status_msg)
    def run(self,context,logger,live_callback=None):
        r=super().run(context,logger,live_callback); r.update(self.metadata); r['status']=self.metadata['status']; return r

def run(context,logger,live_callback=None): return CleanupModule().run(context,logger,live_callback)
