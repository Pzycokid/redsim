import logging
import json
from datetime import datetime
from config import LOG_DIR  # pyre-ignore

def setup_logger(name='RedSim'):
    """Initialises the RedSim text logger, writing to logs/redsim.log."""
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    if getattr(logger, 'is_setup', False):
        return logger
    handler = logging.FileHandler(LOG_DIR / 'redsim.log', mode='a', encoding='utf-8')
    handler.setFormatter(logging.Formatter(
        '%(asctime)s | %(name)-18s | %(levelname)-8s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    logger.addHandler(handler)
    setattr(logger, 'is_setup', True)
    return logger

def log_event(scenario, module, action, status, mitre_technique, details=''):
    """Appends a JSON-Lines event to logs/events.json for SIEM/dashboard ingestion."""
    event = {
        'timestamp': datetime.now().isoformat(),
        'scenario': scenario, 'module': module,
        'action': action, 'status': status,
        'mitre_technique': mitre_technique, 'details': details
    }
    try:
        with open(LOG_DIR / 'events.json', 'a', encoding='utf-8') as f:
            f.write(json.dumps(event) + '\n')
    except Exception as e:
        print(f'[ERROR] log_event failed: {e}')

def log_info(logger, message, scenario='N/A', module='N/A', action='N/A', mitre='N/A', details=''):
    logger.info(message)
    log_event(scenario, module, action, 'success', mitre, details or message)

def log_error(logger, message, scenario='N/A', module='N/A', action='N/A', mitre='N/A', details=''):
    logger.error(message)
    log_event(scenario, module, action, 'failure', mitre, details or message)
