from __future__ import annotations

import logging

import pytest


@pytest.fixture(autouse=True)
def _restore_process_logging(monkeypatch):
    """Keep CLI logging handlers from leaking into later tests' captured streams."""
    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    monkeypatch.setenv("AUTO_PASS_LOG_FILE", "off")
    yield
    for handler in root.handlers:
        if handler not in handlers:
            handler.close()
    root.handlers[:] = handlers
    root.setLevel(level)
