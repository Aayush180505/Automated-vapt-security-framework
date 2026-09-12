"""Shared enumerations for the assessment domain."""

from enum import Enum


class Severity(str, Enum):
    """How serious the issue is if confirmed. Separate from Confidence."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(str, Enum):
    """How certain we are that the observation is accurate. Separate from Severity."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Priority(str, Enum):
    """Remediation order derived from risk score. Separate from Severity."""

    P1 = "p1"
    P2 = "p2"
    P3 = "p3"
    P4 = "p4"
    P5 = "p5"


class ScanStatus(str, Enum):
    """Lifecycle of an in-memory / stored assessment run."""

    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
