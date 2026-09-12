"""Web enumeration package."""

from vapt_framework.enumeration.web.crawler import CrawlLimits, crawl_web
from vapt_framework.enumeration.web.models import WebAttackSurface

__all__ = ["CrawlLimits", "WebAttackSurface", "crawl_web"]
