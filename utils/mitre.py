"""MITRE ATT&CK (Enterprise) helpers for scenario metadata — simulation labels only."""
import re
from typing import Any, Dict, List, Optional
from utils.logger import log_event  # pyre-ignore

ENTERPRISE_TACTICS: List[str] = [
    'Reconnaissance','Resource Development','Initial Access','Execution',
    'Persistence','Privilege Escalation','Defense Evasion','Credential Access',
    'Discovery','Lateral Movement','Collection','Command and Control','Exfiltration','Impact',
]
_TID_RE = re.compile(r'^T\d{4}(?:\.\d{3})?$', re.IGNORECASE)

DEFAULT_MITRE_BY_MODULE: Dict[str,Dict[str,str]] = {
    'recon':               {'tactic':'Discovery','technique_id':'T1046','technique_name':'Network Service Discovery'},
    'credential_access':   {'tactic':'Credential Access','technique_id':'T1110','technique_name':'Brute Force'},
    'lateral_movement':    {'tactic':'Lateral Movement','technique_id':'T1021','technique_name':'Remote Services'},
    'persistence':         {'tactic':'Persistence','technique_id':'T1543','technique_name':'Create or Modify System Process'},
    'privilege_escalation':{'tactic':'Privilege Escalation','technique_id':'T1068','technique_name':'Exploitation for Privilege Escalation'},
    'exfiltration':        {'tactic':'Exfiltration','technique_id':'T1048','technique_name':'Exfiltration Over Alternative Protocol'},
}

def normalize_technique_id(raw: Any) -> Optional[str]:
    if raw is None: return None
    text = str(raw).strip().upper()
    return text if _TID_RE.match(text) else None

def normalize_mitre_blob(raw: Any) -> Optional[Dict[str,str]]:
    if not raw or not isinstance(raw,dict): return None
    tactic=str(raw.get('tactic') or raw.get('tactic_name') or '').strip()
    tid=normalize_technique_id(raw.get('technique_id') or raw.get('id'))
    name=str(raw.get('technique_name') or raw.get('name') or '').strip()
    if not tactic and not tid and not name: return None
    out: Dict[str,str]={}
    if tactic: out['tactic']=tactic
    if tid: out['technique_id']=tid
    if name: out['technique_name']=name
    return out or None

def coerce_params(raw: Any) -> Dict[str,Any]:
    if raw is None: return {}
    return dict(raw) if isinstance(raw,dict) else {}

def resolve_step_mitre(step: Dict[str,Any], module_key: Optional[str]) -> Optional[Dict[str,str]]:
    params = coerce_params(step.get('params'))
    base: Dict[str,str] = dict(DEFAULT_MITRE_BY_MODULE.get(module_key or '', {}))
    explicit = normalize_mitre_blob(step.get('mitre'))
    if explicit: base.update({k:v for k,v in explicit.items() if v})
    return base if base else None

def tactic_is_known(tactic: str) -> bool:
    return tactic.strip() in ENTERPRISE_TACTICS

def validate_mitre_shape(mitre: Optional[Dict[str,str]]) -> List[str]:
    warnings: List[str] = []
    if not mitre: return warnings
    tactic=mitre.get('tactic','')
    if tactic and not tactic_is_known(tactic): warnings.append(f'Unknown tactic: {tactic!r}')
    tid=mitre.get('technique_id','')
    if tid and not normalize_technique_id(tid): warnings.append(f'Bad technique_id format: {tid!r}')
    return warnings
