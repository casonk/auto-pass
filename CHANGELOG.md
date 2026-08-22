# Changelog

All notable changes to `auto-pass` are documented here.

## Unreleased

- Added `bootstrap.sh`, which creates a virtualenv, installs the package in
  editable mode, and verifies the `auto-pass` command runs. The README
  previously documented a bare `python3 -m pip install -e .`, which PEP 668
  causes current Debian, Ubuntu, Arch and openSUSE to refuse outright.
- Added the portfolio-standard governance, continuity, and contributor baseline files.
