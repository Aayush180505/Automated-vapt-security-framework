"""Locate Nmap, build an allowlisted argument list, and execute it."""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Sequence

from vapt_framework.core.exceptions import NmapExecutionError, NmapNotFoundError
from vapt_framework.utils.logging import get_logger

_NMAP_NOT_FOUND = (
    "Nmap was not found on PATH. "
    "Please install Nmap and ensure the executable is available."
)
_MAX_STDERR = 2000
logger = get_logger("vapt_framework.adapters.nmap.runner")


def find_nmap_executable() -> str:
    """Return the Nmap executable path or raise :class:`NmapNotFoundError`."""
    path = shutil.which("nmap") or shutil.which("nmap.exe")
    if not path:
        raise NmapNotFoundError(_NMAP_NOT_FOUND)
    return path


def build_nmap_command(
    target_host: str,
    *,
    nmap_executable: str = "nmap",
    output_path: str = "-",
    port: int | None = None,
) -> list[str]:
    """Build a conservative service-discovery command as an argument list.

    Uses version detection (``-sV``) and XML output. Does not enable NSE
    scripts, OS detection (``-A``), or evasion-oriented options.
    """
    host = (target_host or "").strip()
    if not host:
        raise NmapExecutionError("Nmap service discovery failed.")
    if host.startswith("-"):
        raise NmapExecutionError("Nmap service discovery failed.")

    command = [nmap_executable, "-sV", "-T3", "-oX", output_path]
    if port is not None:
        command.extend(["-p", str(port)])
    command.append(host)
    return command


def run_nmap(command: Sequence[str], timeout: float) -> str:
    """Run ``command`` with ``shell=False`` and return XML from stdout."""
    if not command:
        raise NmapExecutionError("Nmap service discovery failed.")
    logger.info("Executing Nmap")
    logger.debug("Nmap argv: %s", list(command))
    try:
        completed = subprocess.run(
            list(command),
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        logger.error("Nmap timed out after %s seconds", timeout)
        raise NmapExecutionError("Nmap service discovery timed out.") from exc
    except FileNotFoundError as exc:
        raise NmapNotFoundError(_NMAP_NOT_FOUND) from exc
    except PermissionError as exc:
        logger.error("Nmap permission error")
        raise NmapExecutionError("Nmap service discovery failed.") from exc
    except OSError as exc:
        logger.error("Nmap execution error: %s", exc.__class__.__name__)
        raise NmapExecutionError("Nmap service discovery failed.") from exc

    if completed.stderr:
        logger.debug("Nmap stderr (truncated): %s", completed.stderr[:_MAX_STDERR])

    xml_text = completed.stdout or ""
    if completed.returncode != 0 and not _looks_like_xml(xml_text):
        logger.error("Nmap exited with status %s", completed.returncode)
        raise NmapExecutionError("Nmap service discovery failed.")
    if not _looks_like_xml(xml_text):
        raise NmapExecutionError("Nmap service discovery failed.")
    return xml_text


def _looks_like_xml(text: str) -> bool:
    stripped = text.lstrip()
    return stripped.startswith("<?xml") or stripped.startswith("<nmaprun")
