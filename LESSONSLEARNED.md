# LESSONSLEARNED.md

Tracked durable lessons for `auto-pass`.
Unlike `CHATHISTORY.md`, this file should keep only reusable lessons that should change how future sessions work in this repo.

## How To Use

- Read this file after `AGENTS.md` and before `CHATHISTORY.md` when resuming work.
- Add lessons that generalize beyond a single session.
- Keep entries concise and action-oriented.
- Do not use this file for transient status updates or full session logs.

## Lessons

- Document the repository around its real execution, curation, or integration flow instead of only the top-level folder list.
- Keep local-only, private, reference-only, or generated boundaries explicit so published or runtime behavior is not confused with offline material or non-committable inputs.
- Re-run repo-appropriate validation after changing generated artifacts, diagrams, workflows, or other CI-facing files so formatting and compatibility issues are caught before push.

- Document secret-wrapper utilities around three seams: env/profile resolution,
  secret-context resolution, and subprocess execution.
- Show read and write paths separately when create-on-miss behavior is a real
  branch of the implementation.
- Keep local cache files and local env files explicit in the architecture, but
  never inspect or record their secret contents.
- When adding profile-aware downstream integrations, prefer
  `load_config_environment(path, profile=...)` over manually mutating
  `AUTO_PASS_PROFILE` plus a second profile-apply step.
- For direct downstream consumers of `auto-pass`, standardize on a tracked
  `config/auto-pass.example.ini` plus gitignored `config/auto-pass.ini` for
  repo-local defaults; keep older compatibility flows like
  `personal-finance/pf.env.local` separate instead of forcing the same file
  shape everywhere.
- Keep tracked example configs scrubbed of real account identifiers, email
  addresses, hostnames, and live KeePass entry names; use obvious placeholders
  that show the shape without mirroring the operator's private vault layout.
- When scrubbing tracked placeholder entry names, preserve any naming
  conventions that code depends on, such as suffix-based heuristics like
  `@refresh`, so privacy cleanups do not silently weaken runtime behavior.
- When `auto-pass` invokes downstream tools that can themselves resolve
  credentials through `auto-pass`, add an explicit suppression guard so
  notification or audit hooks do not recurse through sibling repos like
  `shock-relay`.
- **Backlog — provisioning service hardening**: The `admin_context` daemon op
  (used by `auto-pass web` to get the master password for direct KeePassXC
  writes) currently gates only on caller UID == daemon owner UID. It should
  additionally verify that `resolve_caller_repo(pid) == "auto-pass"` (i.e.
  the caller is running from within the auto-pass repo) before returning
  credentials. Without this, any process running as the same UID can request
  the master password if it knows the socket path. Implement by adding an
  `admin_repos` list to the allowlist TOML (e.g. `admin_repos = ["auto-pass"]`)
  and checking it in `ProvisioningServer.handle_request` for the `admin_context`
  op.
- For downstream consumers that need multiple vaults, keep a local gitignored
  DB alias index (for example `config/keepass-dbs.local.json`) alongside the
  env/profile file. Let aliases map to vault paths plus optional password-source
  entries in another vault so sibling repos can resolve split-vault access
  without hardcoding local `.kdbx` paths or duplicating secondary-vault
  passwords in repo-specific config.

### Invoking auto-pass from outside its repo root

- `auto-pass get ...` looks for `config/auto-pass.env.local` relative to the shell's CWD.
  Running it from any directory other than the auto-pass repo root causes it to silently
  return empty output instead of an error.
- Always pass `--env-file /path/to/auto-pass/config/auto-pass.env.local` when invoking
  auto-pass from automation scripts or from a different working directory.
- Do not suppress stderr with `2>/dev/null` without also validating that the returned
  value is non-empty; an empty PAT stored as a GitHub secret will fail just as the
  original missing secret did.
