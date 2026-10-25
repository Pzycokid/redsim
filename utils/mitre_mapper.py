# RedSim - MITRE ATT&CK Metadata Mapper
# Maps internal module keys to MITRE technique metadata for logging and reports.

MITRE_MAPPINGS = {
    'recon':               {'technique_id': 'T1595', 'description': 'Active Scanning', 'tactic': 'Reconnaissance'},
    'credential_access':   {'technique_id': 'T1003', 'description': 'OS Credential Dumping', 'tactic': 'Credential Access'},
    'persistence':         {'technique_id': 'T1547', 'description': 'Boot/Logon Autostart Execution', 'tactic': 'Persistence'},
    'lateral_movement':    {'technique_id': 'T1021', 'description': 'Remote Services (SMB)', 'tactic': 'Lateral Movement'},
    'privilege_escalation':{'technique_id': 'T1548', 'description': 'Abuse Elevation Control', 'tactic': 'Privilege Escalation'},
    'defense_evasion':     {'technique_id': 'T1070', 'description': 'Indicator Removal', 'tactic': 'Defense Evasion'},
    'exfiltration':        {'technique_id': 'T1041', 'description': 'Exfiltration Over C2', 'tactic': 'Exfiltration'},
    'ransomware_sim':      {'technique_id': 'T1486', 'description': 'Data Encrypted for Impact', 'tactic': 'Impact'},
    'cleanup':             {'technique_id': 'T1070.004', 'description': 'File Deletion', 'tactic': 'Defense Evasion'},
}

def get_mitre_mapping(module_name: str) -> dict:
    """Returns MITRE metadata for a module key; falls back to a safe placeholder."""
    default = {'technique_id': 'T0000',
               'description': f'Unmapped module: {module_name}',
               'tactic': 'Various/Unknown'}
    return MITRE_MAPPINGS.get(str(module_name).strip().lower(), default)

def get_all_mitre_mappings() -> dict:
    return MITRE_MAPPINGS
