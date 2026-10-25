class RedSimBaseError(Exception):
    """Base exception for all RedSim-specific faults."""
    pass

class ScenarioValidationError(RedSimBaseError):
    """Raised when a JSON scenario fails validation before execution."""
    pass

class ModuleResolutionError(RedSimBaseError):
    """Raised when the engine fails to resolve or load a simulation payload."""
    pass

class ExecutionRuntimeError(RedSimBaseError):
    """Raised when an active payload crashes inside the sandbox."""
    pass
