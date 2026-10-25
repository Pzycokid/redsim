import os, json, sys
from utils.mitre import coerce_params, resolve_step_mitre, validate_mitre_shape  # type: ignore
from utils.path_utils import get_base_dir  # type: ignore

def run_bulk_validation() -> int:
    """Validates all scenario JSON files in scenarios/; returns 0 on success, 1 on errors."""
    sys.path.insert(0, get_base_dir())
    try:
        from scenario_engine import MODULE_MAP  # type: ignore
    except ImportError:
        print('Error: could not import scenario_engine. Run from project root.'); return 1

    scen_dir = os.path.join(get_base_dir(), 'scenarios')
    if not os.path.isdir(scen_dir):
        print(f'No scenarios/ at {scen_dir}'); return 1

    errors, warnings = [], []
    for name in sorted(os.listdir(scen_dir)):
        if not name.lower().endswith('.json'): continue
        try:
            with open(os.path.join(scen_dir, name), 'r', encoding='utf-8') as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            errors.append(f'{name}: invalid JSON - {e}'); continue
        if 'steps' not in data or not isinstance(data['steps'], list):
            errors.append(f'{name}: missing steps array'); continue
        for i, step in enumerate(data['steps'], 1):
            mod = step.get('module')
            if not mod: errors.append(f'{name} step {i}: missing module')
            elif mod not in MODULE_MAP: errors.append(f'{name} step {i}: unknown module {mod!r}')
            mitre = resolve_step_mitre(step, mod)
            for w in validate_mitre_shape(mitre): warnings.append(f'{name} step {i}: {w}')
            coerce_params(step.get('params'))
    if warnings:
        for w in warnings: print(f'  WARN: {w}')
    if errors:
        for e in errors: print(f'  ERROR: {e}')
        return 1
    print('OK: all scenarios passed.')
    return 0
