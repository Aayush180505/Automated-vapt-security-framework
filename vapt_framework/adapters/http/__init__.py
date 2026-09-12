"""HTTP adapter: transport, probing, and service detection."""

from vapt_framework.adapters.http.client import HttpClient
from vapt_framework.adapters.http.models import HTTPResponseInfo, HTTPService
from vapt_framework.adapters.http.probe import (
    detect_http_candidates,
    nmap_indicates_http,
    probe_http_service,
)

__all__ = [
    "HTTPResponseInfo",
    "HTTPService",
    "HttpClient",
    "detect_http_candidates",
    "nmap_indicates_http",
    "probe_http_service",
]
