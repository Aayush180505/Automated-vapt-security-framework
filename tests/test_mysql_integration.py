"""Optional live MySQL checks. Skipped unless VAPT_MYSQL_INTEGRATION=1."""

from __future__ import annotations

import os

import pytest

pytestmark = pytest.mark.integration


@pytest.mark.skipif(
    os.getenv("VAPT_MYSQL_INTEGRATION") != "1",
    reason="Set VAPT_MYSQL_INTEGRATION=1 to run live MySQL tests.",
)
def test_live_mysql_placeholder() -> None:
    pytest.skip("No automated live MySQL fixture is bundled with the suite.")
