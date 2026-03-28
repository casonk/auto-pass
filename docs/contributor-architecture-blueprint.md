# Contributor Architecture Blueprint

This document is a concise map of how `auto-pass` loads local KeePassXC
configuration, resolves the active secret context, and routes read versus write
workflows through `keepassxc-cli`.

## Public Entry Surface

- `src/auto_pass/__main__.py`
- console script `auto-pass`
- `src/auto_pass/cli.py`

These all converge on `cli.main()`, which is the user-facing command router for
`get`, `get-all`, `set`, and `mkdir`.

## Configuration And Context Layer

1. Local config input
   - `config/auto-pass.env.local` is the local-only input surface.
   - `config/auto-pass.env.example` is the tracked documentation surface.
2. Env/profile normalization (`src/auto_pass/envfile.py`)
   - Parses shell-style env assignments.
   - Applies `AUTO_PASS_PROFILE_*` values onto the active
     `AUTO_PASS_KEEPASSXC_*` variables.
   - Preserves compatibility with `PF_KEEPASSXC_*` naming.
3. Secret-context resolution (`src/auto_pass/keepassxc.py`)
   - Resolves database path, password, and key file.
   - Seeds the effective database password from `~/.cache/auto-pass/` when
     available.
   - Falls back to an interactive prompt only when the session allows it.

## Read Lane

- `get` -> `resolve_keepassxc_entry()`
- `get-all` -> `resolve_keepassxc_entry_all_fields()`
- subprocess edge: `keepassxc-cli show`

The read path normalizes attribute aliases such as `username`, `pw`, and `otp`,
then formats stdout as either plain text or JSON.

## Write Lane

- `mkdir` -> `ensure_group()` -> `keepassxc-cli mkdir`
- `set` -> `upsert_keepassxc_entry()`

`upsert_keepassxc_entry()` is the main write workflow:

1. try `keepassxc-cli edit`
2. if the entry is missing, optionally create the parent group path
3. retry through `keepassxc-cli add`

This is the most important internal branch in the repo because it determines
whether writes are treated as updates or as create-on-miss operations.

## Validation Surface

- `tests/test_envfile.py`
- `tests/test_keepassxc.py`
- `.github/workflows/ci.yml`

## Key Entry Points

- `PYTHONPATH=src python -m auto_pass --help`
- `PYTHONPATH=src python -m auto_pass get web/github`
- `PYTHONPATH=src python -m auto_pass set web/github --password-stdin`
- `config/auto-pass.env.example`
- `.github/workflows/ci.yml`

## Validation

```bash
python -m pip install -e .
PYTHONPATH=src python -m auto_pass --help
python -m unittest discover -s tests -v
```
