"""Web enumeration: static crawl and attack-surface models."""

from vapt_framework.enumeration.web.crawler import CrawlLimits, crawl_web
from vapt_framework.enumeration.web.models import (
    Endpoint,
    Form,
    FormField,
    Parameter,
    RobotsEntry,
    WebAttackSurface,
)

__all__ = [
    "CrawlLimits",
    "Endpoint",
    "Form",
    "FormField",
    "Parameter",
    "RobotsEntry",
    "WebAttackSurface",
    "crawl_web",
]
