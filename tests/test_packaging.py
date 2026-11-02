"""The metadata a user installs from: the extras the documentation tells them to ask for."""

from __future__ import annotations

import tomllib
from pathlib import Path

PYPROJECT = tomllib.loads((Path(__file__).resolve().parents[1] / "pyproject.toml").read_text())


def test_the_web_extra_is_declared_where_pip_reads_it():
    # it had been written under [tool.pytest.ini_options], so `auto-pass[web]` installed nothing
    extras = PYPROJECT["project"]["optional-dependencies"]
    assert {"web", "dev"} <= set(extras)
    names = {
        requirement.split("[")[0].split(">")[0].strip().lower() for requirement in extras["web"]
    }
    assert {"fastapi", "uvicorn", "jinja2", "python-multipart"} <= names


def test_the_dev_extra_can_run_the_web_tests():
    names = {
        r.split("[")[0].split(">")[0].strip().lower()
        for r in PYPROJECT["project"]["optional-dependencies"]["dev"]
    }
    assert {"fastapi", "httpx", "jinja2", "python-multipart"} <= names


def test_pytest_options_hold_only_pytest_options():
    allowed = {"testpaths", "pythonpath", "addopts", "markers", "filterwarnings", "minversion"}
    assert set(PYPROJECT["tool"]["pytest"]["ini_options"]) <= allowed
