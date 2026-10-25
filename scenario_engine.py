import time
import importlib
from datetime import datetime
from typing import Dict, Any, Generator
import logging

from utils.exceptions import ModuleResolutionError, ExecutionRuntimeError  # pyre-ignore
from modules import AVAILABLE_MODULES

# Explicit mapping for validate_scenarios.py
MODULE_MAP = AVAILABLE_MODULES


class ScenarioSimulationEngine:
    """
    Core engine: parses scenario JSON, dynamically loads Python modules,
    orchestrates sandboxed payloads, and compiles SIEM telemetry.
    """
    def __init__(self, scenario_data: Dict[str, Any], logger: logging.Logger, safe_mode: bool = True):
        self.scenario_data = scenario_data
        self.logger = logger
        self.safe_mode = safe_mode
        self.context: Dict[str, Any] = {}
        self.results: Dict[str, Any] = {
            'scenario': self.scenario_data.get('name', 'Unknown'),
            'status': 'success', 'timeline': [], 'steps': [],
            'successful_steps': 0, 'failed_steps': 0, 'success_rate': 0.0,
            'total_duration': 0.0, 'risk_score': 0, 'mitre_summary': []
        }
        # Mandatory full-killchain sequence (engine augments missing steps automatically)
        self._FULL_CHAIN = [
            {'module': 'recon',               'technique': 'T1082', 'name': 'System Discovery'},
            {'module': 'credential_access',   'technique': 'T1110', 'name': 'Auth Brute-Force'},
            {'module': 'defense_evasion',     'technique': 'T1218', 'name': 'Binary Proxy Execution'},
            {'module': 'privilege_escalation','technique': 'T1548', 'name': 'Elevation Abuse'},
            {'module': 'lateral_movement',    'technique': 'T1021', 'name': 'Remote Service Discovery'},
            {'module': 'persistence',         'technique': 'T1547', 'name': 'Autostart Hooks'},
            {'module': 'exfiltration',        'technique': 'T1041', 'name': 'Data Staging'},
            {'module': 'ransomware_sim',       'technique': 'T1486', 'name': 'Encrypted Impact'},
            {'module': 'cleanup',             'technique': 'T1070', 'name': 'Sanitize Pipeline'},
        ]
        self._augment_scenario()

    def _augment_scenario(self):
        existing = self.scenario_data.get('steps', [])
        mods = {s.get('module') for s in existing if s.get('enabled', True)}
        augmented = list(existing)
        for m in self._FULL_CHAIN:
            if m['module'] not in mods:
                step = {'id': f'aug_{m["module"]}', 'technique': m['technique'],
                        'name': f'{m["name"]} [Augmented]', 'module': m['module'], 'enabled': True}
                if augmented and augmented[-1].get('module') == 'cleanup':
                    augmented.insert(-1, step)
                else:
                    augmented.append(step)
        self.scenario_data['steps'] = augmented
        self.logger.info(f'Engine augmented scenario to {len(augmented)} steps.')

    def _resolve_module(self, module_path: str, step_id: str):
        if not module_path:
            raise ModuleResolutionError(f'[{step_id}] Missing module attribute.')
        if '..' in module_path or module_path.startswith('/'):
            raise ModuleResolutionError(f'[{step_id}] Illegal module path: {module_path!r}')
        full_name = f'modules.{module_path}'
        try:
            mod = importlib.import_module(full_name)
        except ImportError as e:
            raise ModuleResolutionError(f'Failed to import {full_name}: {e}')
        if not hasattr(mod, 'run'):
            raise ModuleResolutionError(f'{full_name} missing required run() hook.')
        return mod, full_name

    def _execute_step(self, step: Dict[str, Any], index: int, total: int, live_callback=None) -> bool:
        step_id   = step.get('id', f'step_{index}')
        mod_path  = step.get('module', '')
        technique = step.get('technique', 'T0000')
        name      = step.get('name', 'Unnamed Step')
        self.logger.info(f'[{index+1}/{total}] {mod_path} ({technique})')
        t0 = time.time()
        result = {'module': mod_path, 'mitre': technique, 'status': 'failed',
                  'duration': 0.0, 'summary': 'Step failed', 'timestamp': datetime.now().isoformat(),
                  'id': step_id, 'name': name, 'risk_added': 0}
        try:
            mod, _ = self._resolve_module(mod_path, step_id)
            output = mod.run(self.context, self.logger, live_callback=live_callback)
            dur = round(time.time() - t0, 3)
            risk = int(output.get('risk_score', 0))
            result.update({'status': 'success', 'summary': str(output.get('status_msg', '')),
                           'duration': dur, 'risk_added': risk})
            self.results['risk_score'] += risk
            self.results['total_duration'] = round(self.results['total_duration'] + dur, 3)
            self.results['successful_steps'] += 1
            if technique not in self.results['mitre_summary']:
                self.results['mitre_summary'].append(technique)
            self.results['timeline'].append({'timestamp': result['timestamp'],
                                              'step_id': step_id, 'action': f'{technique}: {name}',
                                              'duration_seconds': dur})
            self.results['steps'].append(result)
            return True
        except (ModuleResolutionError, Exception) as e:
            dur = round(time.time() - t0, 3)
            self.results['total_duration'] = round(self.results['total_duration'] + dur, 3)
            self.results['failed_steps'] += 1
            result.update({'status': 'failure', 'summary': str(e), 'duration': dur})
            self.results['steps'].append(result)
            self.logger.error(f'[{step_id}] {e}')
            return False

    def execute_live(self, live_callback=None) -> Generator[Dict[str, Any], None, None]:
        steps = self.scenario_data.get('steps', [])
        total = len(steps)
        self.logger.info(f"Running '{self.results['scenario']}' ({total} steps)")
        yield {'type': 'start', 'scenario': self.results['scenario'], 'total_steps': total,
               'category': self.scenario_data.get('category', ''),
               'attacker_profile': self.scenario_data.get('attacker_profile', '')}
        for i, step in enumerate(steps):
            if not step.get('enabled', True):
                continue
            yield {'type': 'step_start', 'index': i+1, 'module': step.get('module'), 'mitre': step.get('technique')}
            self._execute_step(step, i, total, live_callback)
            if self.results['steps']:
                yield {'type': 'step', 'index': i+1, 'total': total,
                       'success': self.results['steps'][-1]['status'] == 'success',
                       'data': self.results['steps'][-1]}
        s = self.results['successful_steps']
        if total > 0:
            self.results['success_rate'] = round(s / total * 100, 2)
        if self.results['failed_steps'] > 0:
            self.results['status'] = 'partial_failure'
        self.logger.info(f"Done. Status: {self.results['status']}, Risk: {self.results['risk_score']}")
        yield {'type': 'finish', 'results': self.results}

    def execute(self) -> Dict[str, Any]:
        for event in self.execute_live():
            if event['type'] == 'finish':
                return event['results']
        return self.results
