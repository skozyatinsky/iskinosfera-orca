#!/usr/bin/env python3
# ======================================================================
# pytest_junit_evidence_plugin.py — версия 1.0
# Добавляет в JUnit устойчивый node_id и точный outcome, включая XPASS.
# ======================================================================

from __future__ import annotations

import pytest


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_setup(item: pytest.Item) -> None:
    """Attach the collected pytest node ID before any setup-time skip."""
    item.user_properties.append(("node_id", item.nodeid))


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[object]):
    """Persist machine-readable outcomes in JUnit testcase properties."""
    outcome = yield
    report = outcome.get_result()
    if report.when == "call":
        if hasattr(report, "wasxfail"):
            aps_outcome = "xpassed" if report.passed else "xfailed"
        elif report.failed:
            aps_outcome = "failed"
        elif report.skipped:
            aps_outcome = "skipped"
        else:
            aps_outcome = "passed"
        item.user_properties.append(("aps_outcome", aps_outcome))
    elif report.when == "setup" and report.skipped:
        item.user_properties.append(("aps_outcome", "skipped"))
    report.user_properties = list(item.user_properties)
