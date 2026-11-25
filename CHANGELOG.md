# Changelog

All notable changes to `auto-pass` are documented here.

## Unreleased

- Fix the Entries selector scroller to show each complete entry path, wrap long
  paths inside the scroller, and use the portfolio theme's normal font size
  instead of stacking hard-coded body, monospace, and `small` reductions.
- The TPM browser-unlock installer now checks, before installing anything, that the PIN gate unit sets a `PATH` that resolves
  `auto-pass` (a system unit does not inherit the user's `PATH`, and the gate failed every check without it).
- Harden the provisioning daemon's `admin_context` operation: matching the
  daemon UID is no longer sufficient. The caller must resolve to a repository
  named by the allowlist's top-level `admin_repos`, authorization happens before
  vault state is disclosed, and successful handoffs are recorded without the
  returned secret in the owner-only audit trail. Web allowlist edits preserve
  both the admin list and existing `writable_paths` grants.
- Add portfolio-standard cross-platform logging: stderr/journal on Linux,
  automatic owner-private rotating files on macOS and Windows, explicit level
  and file controls, and redaction before either destination emits a record.
  Web/Uvicorn output now uses the same handlers, and daemon policy warnings no
  longer expose repository, vault, or entry names.
- Scoped vaults for K3s: `auto-pass scope list|sync|manifest|verify` builds one small kdbx per service
  from the master (only the entries a scope names, custom attributes kept, history dropped, its own random
  password stored in the master under `auto-pass/scopes/`), applies it as a Secret over `kubectl` stdin, and
  emits RBAC manifests (pod ServiceAccounts with no permissions and no token automount; a sync Role limited to
  the named Secret). Two-way sync is done by auto-pass alone: only the `Password` of `writable` entries that
  already exist, latest modification wins when both sides changed (a future-dated pod timestamp is not believed),
  each pod copy consumed once. `writeback = "secret"` returns the pod's vault through one named Secret
  (`auto-pass scope return` in the pod, `scope pull`/`sync` on the host).
  `auto-pass consolidate [--common]` splits the master's current contents into `common.kdbx` and merges every
  sub-vault into the master under `<alias>/` (plan by default, backups on `--apply`). See `docs/k3s-scoped-vaults.md`, including the K3s `secrets-encryption` steps that need root.
- Provisioning daemon: add a scoped `set` operation (`ProvisioningClient.set`) that replaces the password of an
  existing entry. It needs `writable_paths` in the repo's allowlist block, which is separate from and does not imply
  `allowed_paths`; it never creates an entry, takes the value only over the Unix socket and the vault password over
  stdin, and its audit record names the repo, vault and path but never the value. Restart the daemon (and unlock it)
  for it to take effect.
- Web UI: load the shared portfolio theme and top bar (`/_portfolio/theme.css`, `theme.js`, `chrome.js`) instead of the fixed dark Bootstrap theme, so the UI follows the portfolio theme choice.
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
