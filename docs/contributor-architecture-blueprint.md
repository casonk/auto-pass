# Contributor Architecture Blueprint

This document is a concise map of how `auto-pass` loads local KeePassXC configuration, resolves entries, and exposes CLI workflows.

## High-Level Layers

1. CLI layer (`src/auto_pass/cli.py`)
   - Parses commands such as `get`, `get-all`, `set`, and `mkdir`.
   - User-visible CLI behavior should stay stable unless a change is intentional.
2. Environment-loading layer (`src/auto_pass/envfile.py`)
   - Loads the optional local env file and profile-scoped variables.
   - Compatibility with the `personal-finance` KeePassXC env naming pattern is part of the public behavior.
3. KeePassXC execution layer (`src/auto_pass/keepassxc.py`)
   - Wraps `keepassxc-cli` commands for reading entries, creating groups, and updating entries.
   - Sensitive values must never be logged or committed.
4. Configuration and test layer (`config/auto-pass.env.example`, `tests/`)
   - The tracked env template documents expected variables.
   - Unit tests cover env resolution and KeePassXC command behavior without depending on a real database.

## Key Entry Points

- `PYTHONPATH=src python -m auto_pass --help`
- `python -m unittest discover -s tests -v`
- `config/auto-pass.env.example`
- `.github/workflows/ci.yml`

## Validation

```bash
python -m pip install -e .
PYTHONPATH=src python -m auto_pass --help
python -m unittest discover -s tests -v
```
