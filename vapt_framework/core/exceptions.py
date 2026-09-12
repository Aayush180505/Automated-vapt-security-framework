"""Framework-level exceptions.

CLI code should catch these and print a clean message instead of a traceback.
"""


class VAPTFrameworkError(Exception):
    """Base error for expected, user-facing framework failures."""


class TargetValidationError(VAPTFrameworkError):
    """Raised when a supplied target cannot be validated or normalized."""


class ConfigurationError(VAPTFrameworkError):
    """Raised when application configuration is missing or invalid."""


class NmapNotFoundError(VAPTFrameworkError):
    """Raised when the Nmap executable is not available on PATH."""


class NmapExecutionError(VAPTFrameworkError):
    """Raised when Nmap cannot be executed successfully."""


class NmapParseError(VAPTFrameworkError):
    """Raised when Nmap XML output cannot be parsed."""


class HTTPProbeError(VAPTFrameworkError):
    """Raised when an HTTP probe or request fails."""


class PluginRegistryError(VAPTFrameworkError):
    """Raised when plugin registration is invalid."""


class DatabaseError(VAPTFrameworkError):
    """Base error for MySQL persistence failures."""


class DatabaseConnectionError(DatabaseError):
    """Raised when a MySQL connection cannot be established."""


class DatabaseMigrationError(DatabaseError):
    """Raised when schema initialization fails."""


class DatabasePersistenceError(DatabaseError):
    """Raised when scan data cannot be written or read."""


class ReportError(VAPTFrameworkError):
    """Raised when an HTML report cannot be generated."""
