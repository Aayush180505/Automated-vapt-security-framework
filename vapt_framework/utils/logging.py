"""Centralized logging for the framework."""

from __future__ import annotations

import logging
import sys

_CONFIGURED = False
_FORMAT = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
_DATEFMT = "%Y-%m-%d %H:%M:%S"


def configure_logging(level: str = "INFO") -> None:
    """Configure console logging once for ``vapt_framework`` loggers."""
    global _CONFIGURED
    logger = logging.getLogger("vapt_framework")
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(numeric_level)

    if _CONFIGURED:
        logger.setLevel(numeric_level)
        return

    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(numeric_level)
    handler.setFormatter(logging.Formatter(_FORMAT, datefmt=_DATEFMT))
    logger.addHandler(handler)
    logger.propagate = False
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """Return a child logger under the ``vapt_framework`` namespace."""
    if name.startswith("vapt_framework"):
        return logging.getLogger(name)
    return logging.getLogger(f"vapt_framework.{name}")
