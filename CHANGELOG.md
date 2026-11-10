# Changelog

All notable changes to `auto-pass` are documented here.

## Unreleased

- Web UI Entries page: a browsable, filterable list of entry paths shown as a collapsible
  folder tree (new `GET /entries/list`, paths only, never field values). Looking up an entry now
  builds the result with DOM calls instead of pasting the entry's JSON into an `onclick`
  attribute, which broke "Edit this entry" and put the password in the page; failures show the
  HTTP status, and password and token fields have Show and Copy buttons.
- Web UI Allowlist page no longer returns a server error when a repo uses the simple
  `db = "…"` form with no `allowed_paths`.
- Fix the `web` extra: it had been written under `[tool.pytest.ini_options]`, so
  `pip install "auto-pass[web]"` installed nothing. It is now declared in
  `[project.optional-dependencies]`, and a test keeps it there.
- Web UI: the HTML pages work with current Starlette (they used the removed
  `TemplateResponse(name, context)` call and returned a server error). A login can no
  longer redirect off-site: `next` must be a path on this site. A cookie or token with
  non-ASCII text is refused instead of causing a server error. The allowlist the UI writes
  escapes what it is given, so a path containing a quote, backslash or line break can no
  longer corrupt or inject into the file, and a repository name must be a plain key.
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
