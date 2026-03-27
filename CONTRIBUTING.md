# Contributing

This repository contains KeePassXC-backed automation helpers. Security and compatibility matter more than adding abstraction.

## Getting Started

1. Create or activate a Python environment.
2. Install the project in editable mode:
   ```bash
   python3 -m pip install -e .
   ```
3. Run the test suite:
   ```bash
   python3 -m unittest discover -s tests -v
   ```

## Development Standards

- Preserve compatibility with the existing `AUTO_PASS_KEEPASSXC_*` and `PF_KEEPASSXC_*` environment-variable flows unless the change explicitly removes them.
- Do not commit `config/auto-pass.env.local`, KeePass databases, key files, or cached secrets.
- Keep CLI behavior and README examples in sync.
- Add or update tests whenever env loading, argument parsing, or KeePassXC interactions change.
- Use Conventional Commits such as `feat(cli): add profile override flag` or `fix(env): preserve PF fallback handling`.

## Pull Requests

- Keep each pull request focused on one behavior change.
- Describe any secret-handling or compatibility implications.
- Note how the change was tested.
- Call out README or env-template updates when the user-facing workflow changes.
