# Security Policy

## Reporting

Do not file sensitive disclosures in public issues.

For `auto-pass`, security-sensitive reports should be handled privately by the repository owner.

When reporting an issue, redact any local environment details that are not required to understand the problem.

## Scope

- Do not commit credentials, tokens, private keys, or machine-specific local configuration.
- Do not commit unnecessary absolute filesystem paths, usernames, hostnames, or other local-environment identifiers.
- Treat `CHATHISTORY.md` as local-only operational memory and do not publish it.
- Never commit KeePass database paths, key files, plaintext cache contents, or `config/auto-pass.env.local`.

## Safe Documentation Practices

- Prefer relative paths and location-neutral wording in committed docs when they are operationally sufficient.
- Keep durable workflow guidance in tracked docs such as `AGENTS.md`, `README.md`, and architecture docs.
- Keep transient handoff notes in the local-only repo-root `CHATHISTORY.md` file.
