import re
from typing import Dict, Any, List

def is_safe_path(path_str: str) -> bool:
    """Blocks path traversal, absolute paths, and unsafe characters."""
    if not path_str or not isinstance(path_str, str): return False
    if '..' in path_str: return False
    if path_str.startswith('/') or path_str.startswith('\\') or (len(path_str)>1 and path_str[1]==':'):
        return False
    return bool(re.match(r'^[a-zA-Z0-9_./\\-]+$', path_str))

def validate_step(step: Dict[str, Any], step_index: int = 0) -> List[str]:
    """Validates a single scenario step dict; returns list of error strings."""
    if not isinstance(step, dict):
        return [f'Step {step_index} must be a JSON object']
    errors = []
    for key in ['module', 'enabled']:
        if key not in step: errors.append(f'Step {step_index} missing required key: {key!r}')
    if 'enabled' in step and not isinstance(step['enabled'], bool):
        errors.append(f'Step {step_index}: enabled must be boolean')
    mod = step.get('module')
    if mod and not is_safe_path(str(mod)):
        errors.append(f'Step {step_index}: unsafe module path {mod!r}')
    return errors

def validate_scenario_schema(data: Dict[str, Any]) -> List[str]:
    """Validates a complete scenario dict; returns list of error strings."""
    if not isinstance(data, dict): return ['Root must be a JSON object']
    errors = []
    required = ['name','description','attacker_profile','category','attack_complexity',
                'objectives','tactics','steps','expected_outputs','defensive_value','risk_level']
    for k in required:
        if k not in data: errors.append(f'Missing required field: {k!r}')
    if 'steps' in data:
        steps = data['steps']
        if not isinstance(steps, list): errors.append("'steps' must be an array")
        elif not steps: errors.append("'steps' array is empty")
        else:
            for i, step in enumerate(steps, 1):
                errors.extend(validate_step(step, i))
    return errors
