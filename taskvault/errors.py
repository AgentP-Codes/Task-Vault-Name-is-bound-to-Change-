"""Exception hierarchy. Catch `TaskvaultError` to handle anything taskvault raises on purpose."""


class TaskvaultError(Exception):
    """Base class for taskvault errors."""
