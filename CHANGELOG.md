# Changelog

All notable changes to `auto-pass` are documented here.

## Unreleased

- Add `auto-pass check-access`, which reports every configured vault this login
  cannot read or write, with the fix for each (`--json` for tools). `--fix-acl`
  adds a default ACL entry for the login on vault directories it owns so a file
  rewritten by another account, such as a sync service, stays readable. Exits 1
  on any finding, so an audit can call it.
- Include the optional web UI templates in built wheels so `auto-pass[web]`
  works after installation from a package index.
- Added `bootstrap.sh`, which creates a virtualenv, installs the package in
  editable mode, and verifies the `auto-pass` command runs. The README
  previously documented a bare `python3 -m pip install -e .`, which PEP 668
  causes current Debian, Ubuntu, Arch and openSUSE to refuse outright.
- Added the portfolio-standard governance, continuity, and contributor baseline files.
