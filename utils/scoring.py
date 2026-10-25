"""RedSim scoring utilities — simulation-only, no real-world evaluation."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

def _clamp(v,lo,hi): return max(lo,min(hi,v))
def _level(s): return 'High' if s>=70 else 'Medium' if s>=40 else 'Low'
def _r(v): return float(f'{v:.2f}')

@dataclass(frozen=True)
class Profile:
    base_risk: float
    base_detection_resistance: float
    avg_time_seconds: float

MODULE_PROFILES: Dict[str,Profile] = {
    'recon':               Profile(20,30,3.0),
    'credential_access':   Profile(55,45,2.8),
    'lateral_movement':    Profile(65,50,3.2),
    'privilege_escalation':Profile(75,58,2.7),
    'persistence':         Profile(60,48,2.9),
    'exfiltration':        Profile(70,60,3.4),
}

def _lower(v): return '' if v is None else str(v).strip().lower()

def _method_modifiers(module_key:str, params:Dict[str,Any]) -> Tuple[float,float]:
    method=_lower(params.get('method') or params.get('mechanism') or params.get('technique') or params.get('source') or params.get('channel'))
    r,d=0.0,0.0
    if module_key=='recon':
        if 'active' in method or 'scan' in method: r+=15;d-=10
        if 'passive' in method: d+=8;r-=5
    elif module_key=='credential_access':
        if 'brute' in method or 'spray' in method: r+=20;d-=12
        if 'phish' in method: r+=10;d+=5
        if 'insider' in method: r+=5;d+=15
    elif module_key=='lateral_movement':
        if 'smb' in method: r+=10;d+=8
        if 'psexec' in method: r+=15;d-=5
        if 'powershell' in method or 'winrm' in method: r+=8;d+=12
    elif module_key=='persistence':
        if 'scheduled' in method: r+=12;d-=7
        if 'registry' in method: r+=6;d+=10
        if 'startup' in method: r+=8;d+=6
    elif module_key=='privilege_escalation':
        if 'token' in method: r+=8;d+=12
        if 'admin' in method: r+=12;d+=2
    elif module_key=='exfiltration':
        if 'dns' in method: r+=8;d+=15
        if 'http' in method: r+=15;d-=8
        if 'file' in method or 'scp' in method: r+=10;d+=2
    return r,d

def score_step(module_key:str, status:str, params:Dict[str,Any]) -> Dict[str,Any]:
    p=MODULE_PROFILES.get(module_key,Profile(50,40,3.0))
    rd,dd=_method_modifiers(module_key,params)
    if status=='success': dd+=5
    else: rd+=5
    rs=_clamp(p.base_risk+rd,0,100)
    ds=_clamp(p.base_detection_resistance+dd,0,100)
    return {'risk_score':_r(rs),'risk_level':_level(rs),
            'detection_resistance_score':_r(ds),'detection_resistance_level':_level(ds),
            'estimated_step_time_seconds':p.avg_time_seconds}

def score_run(step_results:List[Dict[str,Any]]) -> Dict[str,Any]:
    if not step_results:
        return {'estimated_execution_time_seconds':0.0,'overall_risk_score':0.0,
                'overall_risk_level':'Low','overall_detection_resistance_score':0.0,
                'overall_detection_resistance_level':'Low','per_step_scoring':[]}
    per,wr,wd,tw,tt=[],.0,.0,.0,.0
    for item in step_results:
        s=score_step(str(item.get('module','')),str(item.get('status','')),
                     item.get('params') if isinstance(item.get('params'),dict) else {})
        per.append(s); st=float(s['estimated_step_time_seconds'])
        tt+=st; wr+=st*float(s['risk_score']); wd+=st*float(s['detection_resistance_score']); tw+=st
    if len(step_results)>1: tt+=1.2*(len(step_results)-1)
    or_=wr/tw if tw else 0; od=wd/tw if tw else 0
    return {'estimated_execution_time_seconds':_r(tt),'overall_risk_score':_r(or_),
            'overall_risk_level':_level(or_),'overall_detection_resistance_score':_r(od),
            'overall_detection_resistance_level':_level(od),'per_step_scoring':per}
