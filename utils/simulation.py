import random
from typing import Optional

# Per-step success rate for simulated uncertainty.
# At 0.85, long scenarios usually complete while seeing occasional step failures.
STEP_SUCCESS_PROBABILITY = 0.85

def uncertain_success(probability: Optional[float] = None) -> bool:
    """Returns True with `probability` chance; defaults to STEP_SUCCESS_PROBABILITY."""
    threshold = STEP_SUCCESS_PROBABILITY if probability is None else probability
    return random.random() < threshold
