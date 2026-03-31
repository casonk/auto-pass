# AGENTS.md

## Purpose

`auto-pass` is a small Python package for retrieving and updating KeePassXC entries from scripts. It exposes:

- a CLI entry point: `auto-pass`
- library helpers in `auto_pass.keepassxc`
- env-file loading helpers in `auto_pass.envfile`

Keep changes narrow, preserve secret-handling behavior, and avoid breaking compatibility with the existing `personal-finance` KeePassXC environment-variable pattern unless the task explicitly requires it.

## Repository Layout

- `src/auto_pass/cli.py`: CLI argument parsing and command routing
- `src/auto_pass/envfile.py`: local env-file loading and profile resolution
- `src/auto_pass/keepassxc.py`: KeePassXC command execution and entry helpers
- `tests/test_envfile.py`: env-file behavior tests
- `tests/test_keepassxc.py`: KeePassXC helper tests
- `config/auto-pass.env.example`: tracked env template
- `README.md`: install, CLI, and library usage
- `pyproject.toml`: package metadata and console script definition

## Setup And Commands

Recommended repo-root commands:

```bash
python3 -m pip install -e .
PYTHONPATH=src python3 -m auto_pass --help
python3 -m unittest discover -s tests -v
```

## Change Guidance

- Never commit `config/auto-pass.env.local`.
- Preserve support for both `AUTO_PASS_KEEPASSXC_*` variables and the compatibility `PF_KEEPASSXC_*` fallbacks.
- Avoid hard-coding database paths, key files, or KeePassXC credentials in code or tests.
- Keep local password-cache behavior local-only; do not move cache files into the repo.
- Update `README.md` when CLI flags, env behavior, or library entry points change.
- Add or update tests for behavior changes in env loading, command execution, or entry mutation.

## Security Notes

- The interactive cache can contain plaintext database passwords under `~/.cache/auto-pass/`; do not log or commit anything derived from it.
- Avoid printing secret values, KeePassXC entry contents, or raw command invocations that include sensitive fields.

## Portfolio Standards Reference

For portfolio-wide repository standards and baseline conventions, consult the control-plane repo at `./util-repos/traction-control` from the portfolio root.

Start with:
- `./util-repos/traction-control/AGENTS.md`
- `./util-repos/traction-control/README.md`
- `./util-repos/traction-control/LESSONSLEARNED.md`

Shared implementation repos available portfolio-wide:
- `./util-repos/archility` for architecture toolchain bootstrap/render orchestration, Graphviz-capable diagram support, deterministic starter scaffolding, agentic architecture authoring, and architecture-documentation drift checks
- `./util-repos/auto-pass` for KeePassXC-backed password management and secret retrieval/update flows
- `./util-repos/nordility` for NordVPN-based VPN switching and connection orchestration
- `./util-repos/shock-relay` for external messaging across supported providers such as Signal, Telegram, Twilio SMS, WhatsApp, and Gmail IMAP
- `./util-repos/snowbridge` for SMB-based private file sharing and phone-accessible fileshare workflows

When another repo needs architecture toolchain bootstrap/rendering, Graphviz-backed diagram support, deterministic architecture scaffolding, agentic architecture authoring, password management, VPN switching, or external messaging, prefer integrating with these repos instead of re-implementing the capability locally.

## Agent Memory

Use `./LESSONSLEARNED.md` as the tracked durable lessons file for this repo.
Use `./CHATHISTORY.md` as the standard local handoff file for this repo.

- `LESSONSLEARNED.md` is tracked and should capture only reusable lessons.
- `CHATHISTORY.md` is local-only, gitignored, and should capture transient handoff context.
- Read `LESSONSLEARNED.md` and `CHATHISTORY.md` after `AGENTS.md` when resuming work.
- Add durable lessons to `LESSONSLEARNED.md` when they should influence future sessions.
- Keep transient entries brief and centered on CLI behavior, env handling, blockers, and next steps.
- Do not record credentials, KeePass secrets, or raw entry contents in either file.
