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
- Prepare manual-assisted password rotations with provider URLs and explicit
  password-policy requirements.
- Promote or discard pending rotation passwords without overwriting the real
  password until the operator confirms the provider-side change succeeded.
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

For downstream repos that need to reference multiple vaults without hardcoding
paths, `auto-pass` can also keep a local gitignored DB alias index at
`config/keepass-dbs.local.json`. Start from the tracked
`config/keepass-dbs.example.json`. This index is a library helper for sibling
repos today: `auto_pass.load_database_index(...)` and
`auto_pass.resolve_database_alias(...)` expose alias metadata such as the
target database path and an optional source entry that holds that vault's
password in another KeePass database.

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
3. `src/auto_pass/dbindex.py` optionally loads `config/keepass-dbs.local.json`
   so downstream repos can map logical vault aliases such as `finance` or
   `infra` to local database paths and password-source metadata.
4. `src/auto_pass/keepassxc.py` resolves the effective KeePassXC context from
   `AUTO_PASS_KEEPASSXC_*` or compatibility `PF_KEEPASSXC_*` values, then
   optionally seeds the database password from the local cache under
   `~/.cache/auto-pass/` or from an interactive prompt.
5. `src/auto_pass/notifications.py` optionally sends audit notifications
   through `shock-relay` for successful password-bearing reads, while
   suppressing nested notifications inside the helper subprocesses.
6. Read commands (`get`, `get-all`) call `keepassxc-cli show`, normalize
   field aliases, and then fire the notification hook when the requested data
   included the KeePass `Password` field.
7. Write commands (`set`, `mkdir`) call `keepassxc-cli edit` first, then create
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

Configure persistent rotation defaults in KeePass:

```bash
auto-pass rotate configure web/github \
  --length 32 \
  --homepage-url https://github.com/login \
  --reset-url https://github.com/settings/security \
  --rotation-interval-days 180
```

That creates or updates a companion registry entry at
`web/github@rotation-config`. The registry entry stores non-secret defaults in
Notes as JSON so future rotations can reuse the same password policy and
provider URLs.

Inspect the persistent registry:

```bash
auto-pass rotate show-config web/github
auto-pass rotate show-config web/github --json
```

Discover registries and see which ones are due:

```bash
auto-pass rotate list-configs
auto-pass rotate list-configs --group web --due-within-days 30
auto-pass rotate list-configs --json
```

Sync due registries into the Clockwork server-backed to-do list:

```bash
auto-pass rotate sync-todo \
  --todo-file ~/git/util-repos/clockwork/config/todo.json \
  --due-within-days 30
```

That command manages a `Password Rotation` category inside the Clockwork to-do
JSON. Successful `rotate promote` runs now refresh the registry timestamp and
upgrade the registry trust marker to `manual/high`, so completed rotations drop
out of the due list on the next sync.

Bootstrap a registry from the current password:

```bash
auto-pass rotate infer-config web/github --rotation-interval-days 180
```

That command reads the current KeePass password and entry URL, derives a
conservative baseline policy from the observed character groups and length, and
writes the result into `web/github@rotation-config`. Inferred registries are
tagged with `policy_source=inferred-from-current-password` and
`policy_confidence=low`.

Prepare a manual-assisted rotation from the registry:

```bash
auto-pass rotate prepare web/github
```

You can still override the registry per rotation:

```bash
auto-pass rotate prepare web/github \
  --length 32 \
  --special-chars '!@#$%^&*()-_=+[]{}:,.?' \
  --reset-url https://github.com/settings/security \
  --homepage-url https://github.com/login
```

That command creates a companion entry at `web/github@rotation-pending`. The
pending entry stores the generated candidate password in its password field and
stores non-secret rotation metadata in Notes as JSON.

Check pending rotation state:

```bash
auto-pass rotate status web/github
auto-pass rotate status web/github --json
```

After you change the password at the provider and verify the new login works,
promote the pending password into the real entry:

```bash
auto-pass rotate promote web/github
```

If the provider-side change fails or you want to abandon the candidate, discard
the pending companion entry:

```bash
auto-pass rotate discard web/github
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

## Rotation Notes

The current rotation flow is intentionally conservative:

- Persistent defaults live in KeePass itself via `<entry>@rotation-config`.
- `rotate infer-config` can seed that registry from the currently stored
  password, but the result is only an observed baseline.
- Password requirements are provided at rotation time through CLI flags.
- Unspecified rotation-time flags fall back to the KeePass-backed registry.
- The real entry password is not overwritten during `rotate prepare`.
- Promotion is an explicit second step after a manual/provider-side change.
- Provider metadata such as homepage and reset URLs are stored with the pending
  rotation so a future provider-aware workflow has a stable place to read from.
- Inferred registry values are hints, not proof of the provider's full policy;
  a successful future rotation is what should upgrade the config from inferred
  to verified.
- `rotate promote` refreshes `updated_at` in the registry and persists the
  successful pending policy as `manual/high`.

## Next

The next layer is provider-aware automation on top of the current registry:
site-specific adapters, requirement discovery, and a controlled path from
manual-assisted rotations toward limited safe auto-rotation.
