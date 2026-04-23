# auto-pass

KeePassXC-backed password automation helpers.

This repo is intentionally starting with the part that is already proven in
`personal-finance`: reliable
`keepassxc-cli` wrappers for reading entries, prompting for the database
password once, caching that password locally for interactive use, and creating
or updating entries from scripts.

Consent reference: [`../../doc-repos/my-consent/credentials-and-secrets.md`](../../doc-repos/my-consent/credentials-and-secrets.md) documents the explicit consent covering personal credential, secret, and secure-store processing handled by this repo.

## Current Scope

- Read one or more fields from a KeePassXC entry.
- Read all fields from a KeePassXC entry.
- Create or update entries through `keepassxc-cli`.
- Create parent group paths automatically when adding entries.
- Reuse the same KeepassXC environment variable pattern used by
  `personal-finance`.

## Environment

The CLI now auto-loads a local env file from `config/auto-pass.env.local` if it
exists. The tracked template lives at `config/auto-pass.env.example`.

Primary env vars:

- `AUTO_PASS_KEEPASSXC_DB_PATH`
- `AUTO_PASS_KEEPASSXC_DB_PASSWORD`
- `AUTO_PASS_KEEPASSXC_KEY_FILE`

Compatibility fallbacks from `personal-finance` are also accepted:

- `PF_KEEPASSXC_DB_PATH`
- `PF_KEEPASSXC_DB_PASSWORD`
- `PF_KEEPASSXC_KEY_FILE`

For multiple KeePass databases, use profile-scoped values in the local env file:

```bash
AUTO_PASS_PROFILE=personal
AUTO_PASS_PROFILE_PERSONAL_KEEPASSXC_DB_PATH=/path/to/personal.kdbx
AUTO_PASS_PROFILE_PERSONAL_KEEPASSXC_DB_PASSWORD=replace-me-personal

AUTO_PASS_PROFILE_WORK_KEEPASSXC_DB_PATH=/path/to/work.kdbx
AUTO_PASS_PROFILE_WORK_KEEPASSXC_DB_PASSWORD=replace-me-work
```

When `AUTO_PASS_PROFILE=personal`, the CLI maps the `PERSONAL` values to the
active `AUTO_PASS_KEEPASSXC_*` env vars before running the command. Profile
names are normalized to uppercase with non-alphanumeric characters replaced by
underscores.

For one-off commands, `--profile` overrides the active profile without editing
the env file:

```bash
auto-pass --profile work get web/github
auto-pass list-profiles
```

Explicitly exported `AUTO_PASS_KEEPASSXC_*` values still take precedence over
profile-mapped defaults.

Interactive runs cache the KeePass database password in a local JSON file under
`~/.cache/auto-pass/` by default, with `0600` permissions. The cache contains
the database password in plaintext, so this should stay local-only.

Optional password-retrieval notifications can be sent through the sibling
`shock-relay` repo. When `AUTO_PASS_NOTIFY_PASSWORD_RETRIEVAL=1` is set,
successful reads that include the KeePass `Password` field send an audit
message to the configured email and/or Signal recipients. The audit payload
includes entry path, active profile, vault basename, host, user, pid, and
timestamp, but never the secret value itself.

The notification hook sets a suppression env var before invoking
`shock-relay`, so `shock-relay` can still resolve its own Gmail credentials
through `auto-pass` without recursively sending nested alerts.
For Signal, set `AUTO_PASS_NOTIFY_PASSWORD_RETRIEVAL_SIGNAL_TO=note-to-self`
to send the audit message to the local Signal account defined in the
`shock-relay` Signal config.

## Install

```bash
python3 -m pip install -e .
```

Or run directly from the repo without installing:

```bash
PYTHONPATH=src python3 -m auto_pass --help
```

## Architecture Summary

`auto-pass` is a thin CLI and library facade over a few stable internal seams:

1. `auto-pass` and `python -m auto_pass` enter through `src/auto_pass/cli.py`.
2. `src/auto_pass/envfile.py` optionally loads `config/auto-pass.env.local`,
   applies `AUTO_PASS_PROFILE_*` mappings, supports CLI profile overrides, and
   preserves shell-exported values as the highest-precedence overrides.
3. `src/auto_pass/keepassxc.py` resolves the effective KeePassXC context from
   `AUTO_PASS_KEEPASSXC_*` or compatibility `PF_KEEPASSXC_*` values, then
   optionally seeds the database password from the local cache under
   `~/.cache/auto-pass/` or from an interactive prompt.
4. `src/auto_pass/notifications.py` optionally sends audit notifications
   through `shock-relay` for successful password-bearing reads, while
   suppressing nested notifications inside the helper subprocesses.
5. Read commands (`get`, `get-all`) call `keepassxc-cli show`, normalize
   field aliases, and then fire the notification hook when the requested data
   included the KeePass `Password` field.
6. Write commands (`set`, `mkdir`) call `keepassxc-cli edit` first, then create
   missing parent groups and fall back to `keepassxc-cli add` when the entry
   does not already exist.

The tests intentionally mock subprocess behavior instead of depending on a real
KeePass database, so the main contract here is command construction, env
resolution, and secret-handling behavior.

The CLI loads `config/auto-pass.env.local` automatically. To use a different
file or disable file loading:

```bash
PYTHONPATH=src python3 -m auto_pass --env-file /path/to/other.env get web/github
PYTHONPATH=src python3 -m auto_pass --no-env-file get web/github
PYTHONPATH=src python3 -m auto_pass --profile work get web/github
PYTHONPATH=src python3 -m auto_pass list-profiles
```

## CLI Usage

Read username + password:

```bash
auto-pass get web/github
auto-pass --profile work get web/github
```

List available profiles:

```bash
auto-pass list-profiles
auto-pass list-profiles --json
```

Read a specific field:

```bash
auto-pass get web/github --field username
auto-pass get web/github --field otp
```

Read all fields as JSON:

```bash
auto-pass get-all web/github
```

Enable password-retrieval notifications through `shock-relay`:

```bash
AUTO_PASS_NOTIFY_PASSWORD_RETRIEVAL=1
AUTO_PASS_NOTIFY_PASSWORD_RETRIEVAL_EMAIL_TO=alerts@example.com
AUTO_PASS_NOTIFY_PASSWORD_RETRIEVAL_SIGNAL_TO=note-to-self
AUTO_PASS_NOTIFY_SHOCK_RELAY_ROOT=/path/to/shock-relay
```

Create or update an entry:

```bash
auto-pass set web/github \
  --username octocat \
  --password-stdin \
  --url https://github.com
```

Create a group path explicitly:

```bash
auto-pass mkdir web
```

## Library Usage

```python
from auto_pass import resolve_keepassxc_entry, upsert_keepassxc_entry

creds = resolve_keepassxc_entry(
    entry="web/github",
    attrs_map={"username": "username", "password": "password"},
)

mode = upsert_keepassxc_entry(
    "web/github",
    username="octocat",
    password="new-secret",
    url="https://github.com",
)
```

## Tests

```bash
python3 -m unittest discover -s tests -v
```

See `docs/contributor-architecture-blueprint.md` and
`docs/diagrams/repo-architecture.{puml,drawio}` for the repo-specific
architecture surfaces.

## Next

The obvious next layer is higher-level password automation on top of this
module: syncing browser credentials, rotating selected entries, and config-
driven secret workflows. The KeePassXC integration here is meant to be the
shared base for that work.
