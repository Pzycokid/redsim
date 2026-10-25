from abc import ABC, abstractmethod
from typing import Dict, Any
import logging

# RedSim - Abstract Module Archetype
class BaseSimulationModule(ABC):
    def __init__(self, technique_name: str, base_risk_score: int = 10):
        self.technique = technique_name
        self.risk_score = base_risk_score
        self.status_msg = 'Module initialized.'

    @abstractmethod
    def execute(self, context: Dict[str, Any], logger: logging.Logger, live_callback=None) -> None:
        pass

    def run(self, context: Dict[str, Any], logger: logging.Logger, live_callback=None) -> Dict[str, Any]:
        try:
            self.execute(context, logger, live_callback=live_callback)
            if not self.status_msg: self.status_msg = 'Completed.'
            return {'status_msg': self.status_msg, 'risk_score': self.risk_score}
        except Exception as e:
            logger.error(f'Module {self.technique} exception: {e}')
            return {'status_msg': f'CRITICAL FAILURE: {str(e)}', 'risk_score': 0}
