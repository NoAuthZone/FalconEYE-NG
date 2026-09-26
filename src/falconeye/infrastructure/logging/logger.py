"""
FalconEYE Logging Infrastructure.

Provides centralized logging with:
- Dual output: Human-readable console + JSON file
- Daily log rotation with 30-day retention
- Correlation IDs for request tracing
- Structured metrics embedded in logs
- Singleton pattern for global access

Design Decisions:
- Use Python's standard logging module (naturally buffered)
- Console: Human-readable for developers
- File: JSON for programmatic parsing and analysis
- Thread-safe via threading.Lock
"""

import json
import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional, Any, Dict
from datetime import datetime, timezone
import threading

from .context import LogContext


class JSONFormatter(logging.Formatter):
    """
    Custom formatter that outputs logs in JSON format.

    Includes:
    - Standard fields (timestamp, level, logger, message)
    - Extra fields (command_id, project_id, metrics, etc.)
    - Exception info if present
    """

    def format(self, record: logging.LogRecord) -> str:
        """
        Format log record as JSON.

        Args:
            record: Log record to format

        Returns:
            JSON string representation of log record
        """
        log_data = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add extra fields if present
        for key, value in record.__dict__.items():
            if key not in [
                "name", "msg", "args", "created", "filename", "funcName",
                "levelname", "levelno", "lineno", "module", "msecs",
                "pathname", "process", "processName", "relativeCreated",
                "thread", "threadName", "exc_info", "exc_text", "stack_info"
            ]:
                log_data[key] = value

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
                "traceback": self.formatException(record.exc_info)
            }

        return json.dumps(log_data)


class HumanReadableFormatter(logging.Formatter):
    """
    Human-readable formatter for console output.

    Format: YYYY-MM-DD HH:MM:SS - LEVEL - message
    """

    def __init__(self):
        """Initialize formatter with timestamp, level, and message."""
        super().__init__(
            fmt='%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )


class FalconEyeLogger:
    """
    Centralized logging for FalconEYE.

    Singleton pattern ensures only one logger instance exists.
    Provides dual output: console (human-readable) and file (JSON).

    Features:
    - Daily log rotation
    - 30-day retention
    - Structured logging with extra fields
    - Thread-safe

    Example:
        >>> logger = FalconEyeLogger.get_instance(
        ...     level="INFO",
        ...     log_file=Path("falconeye.log")
        ... )
        >>> logger.info("Processing file", extra={"file_path": "test.py"})
    """

    _instance: Optional['FalconEyeLogger'] = None
    _lock: threading.Lock = threading.Lock()

    def __init__(
        self,
        level: str = "INFO",
        log_file: Optional[Path] = None,
        console: bool = True,
        rotation: str = "daily",
        retention_days: int = 30,
    ):
        """
        Initialize FalconEYE logger.

        Args:
            level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            log_file: Path to log file (optional)
            console: Enable console output (default: True)
            rotation: Log rotation strategy (default: "daily")
            retention_days: Days to retain logs (default: 30)
        """
        self._configure(level, log_file, console, rotation, retention_days)

    def _configure(
        self,
        level: str,
        log_file: Optional[Path],
        console: bool,
        rotation: str,
        retention_days: int,
    ) -> None:
        """(Re)build handlers. Safe to call again on the singleton."""
        self.log_file = Path(log_file).expanduser() if log_file else None
        log_file = self.log_file
        self.logger = logging.getLogger("falconeye")
        self.logger.setLevel(getattr(logging, level.upper()))
        self.logger.propagate = False  # Don't propagate to root logger

        # Close and clear any existing handlers
        for handler in list(self.logger.handlers):
            try:
                handler.close()
            except Exception:
                pass
        self.logger.handlers.clear()

        # Add console handler
        if console:
            console_handler = logging.StreamHandler(sys.stderr)
            console_handler.setLevel(getattr(logging, level.upper()))
            console_handler.setFormatter(HumanReadableFormatter())
            self.logger.addHandler(console_handler)

        # Add file handler with rotation
        if log_file:
            log_file = Path(log_file)
            log_file.parent.mkdir(parents=True, exist_ok=True)

            if rotation == "daily":
                # TimedRotatingFileHandler for daily rotation
                file_handler = logging.handlers.TimedRotatingFileHandler(
                    filename=str(log_file),
                    when='midnight',  # Rotate at midnight
                    interval=1,       # Every day
                    backupCount=retention_days,  # Keep last N days
                    encoding='utf-8'
                )
            else:
                # Regular FileHandler (no rotation)
                file_handler = logging.FileHandler(
                    str(log_file),
                    encoding='utf-8'
                )

            file_handler.setLevel(logging.DEBUG)  # File gets everything
            file_handler.setFormatter(JSONFormatter())
            self.logger.addHandler(file_handler)

    @classmethod
    def get_instance(
        cls,
        level: str = "INFO",
        log_file: Optional[Path] = None,
        console: bool = True,
        rotation: str = "daily",
        retention_days: int = 30,
    ) -> 'FalconEyeLogger':
        """
        Get singleton instance of FalconEyeLogger.

        Thread-safe singleton implementation.

        Args:
            level: Log level
            log_file: Path to log file
            console: Enable console output
            rotation: Rotation strategy
            retention_days: Days to retain

        Returns:
            Singleton FalconEyeLogger instance
        """
        if cls._instance is None:
            with cls._lock:
                # Double-check locking
                if cls._instance is None:
                    cls._instance = cls(
                        level=level,
                        log_file=log_file,
                        console=console,
                        rotation=rotation,
                        retention_days=retention_days,
                    )
                    return cls._instance

        # The singleton is usually created early by adapters calling
        # get_instance() without arguments (no log file). When the CLI later
        # passes the configured log file, apply it instead of silently
        # ignoring it - otherwise falconeye.log is never written.
        if log_file is not None:
            with cls._lock:
                current = getattr(cls._instance, "log_file", None)
                if current is None or Path(current).resolve() != Path(log_file).expanduser().resolve():
                    cls._instance._configure(
                        level, log_file, console, rotation, retention_days
                    )
        return cls._instance

    def _merge_context(self, kwargs: Dict[str, Any]) -> Dict[str, Any]:
        """
        Merge LogContext into kwargs['extra'].

        Context fields are added to extra, but explicit extra fields
        take precedence over context fields.

        Args:
            kwargs: Logging kwargs (may contain 'extra' dict)

        Returns:
            Updated kwargs with merged context
        """
        # Get current context
        context = LogContext.get_context()

        if context:
            # Get existing extra or create new dict
            extra = kwargs.get('extra', {})

            # Merge context into extra (explicit extra takes precedence)
            merged_extra = {**context, **extra}

            # Update kwargs
            kwargs = kwargs.copy()
            kwargs['extra'] = merged_extra

        return kwargs

    def debug(self, message: str, **kwargs):
        """Log debug message with automatic context injection."""
        kwargs = self._merge_context(kwargs)
        self.logger.debug(message, **kwargs)

    def info(self, message: str, **kwargs):
        """Log info message with automatic context injection."""
        kwargs = self._merge_context(kwargs)
        self.logger.info(message, **kwargs)

    def warning(self, message: str, **kwargs):
        """Log warning message with automatic context injection."""
        kwargs = self._merge_context(kwargs)
        self.logger.warning(message, **kwargs)

    def error(self, message: str, **kwargs):
        """Log error message with automatic context injection."""
        kwargs = self._merge_context(kwargs)
        self.logger.error(message, **kwargs)

    def critical(self, message: str, **kwargs):
        """Log critical message with automatic context injection."""
        kwargs = self._merge_context(kwargs)
        self.logger.critical(message, **kwargs)


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance for the given name.

    This is a helper function that returns the underlying Python logger
    configured by FalconEyeLogger.

    Args:
        name: Logger name (typically __name__)

    Returns:
        Configured logger instance

    Example:
        >>> logger = get_logger(__name__)
        >>> logger.info("Processing started")
    """
    return logging.getLogger(f"falconeye.{name}")
