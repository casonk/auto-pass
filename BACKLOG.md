# BACKLOG.md

Portfolio backlog for this repository. Pending items are candidates for execution —
manually or via crew-chief. Entries sourced from archility audit are tagged
`[archility:YYYY-MM-DD]`; manual entries use `[manual:YYYY-MM-DD]`.

The archility twice-weekly job populates this file automatically via `archility audit --write-backlog`.
To execute a backlog item with crew-chief: `crew-chief agent "Work on item: <item text>"`.
Mark items `[x]` when complete and move them to Done.

## Pending

- [ ] [manual:2026-11-24] **Reboot-test the installed TPM browser unlock path.** The sealed credentials and system
  services are installed, enabled, and healthy. Reboot once, leave the vault locked, and prove the Auto Pass keypad
  opens and its `/daemon` page can unlock the daemon. This completes the paired wiring-harness sealed-PIN backlog
  item.

- [ ] [codecov:2026-11-20] **Raise patch coverage on PR #30: 47.5581% patched, 451 changed lines have no test coverage.** Files: src/auto_pass/consolidate.py (122 missing, 0%), src/auto_pass/cli.py (120 missing, 21.05%), src/auto_pass/kdbx.py (97 missing, 29.71%), src/auto_pass/scopes.py (81 missing, 70.86%), src/auto_pass/k8s.py (31 missing, 81.76%). Add tests for the uncovered lines. (codecov-pr:30, https://github.com/casonk/auto-pass/pull/30#issuecomment-7052159126)
- [ ] [manual:2026-10-15] **Ask GitHub Support to purge pre-rewrite commits** — this
  repository's published history was rewritten (most recently on 2026-10-15,
  to remove per-commit AI attribution trailers). GitHub keeps serving the old
  commits to anyone with a hash, and through the read-only `refs/pull/*` refs
  of earlier pull requests, until Support garbage-collects them. The request
  is filed once for the whole portfolio from traction-control's backlog; mark
  this done when an old hash returns 404 here. Never push an old clone's
  history back.

- [ ] [manual:2026-11-11] **Strip AI-attribution trailers added after the 2026-10-15 rewrite** — assistant
  co-author and session trailers are on the squash-merge message of the web fixes (#23). A pull
  request cannot remove them, since a merge only adds commits. Removing them means rewriting `main`:
  a trailer-only filter leaves every tree identical, but needs the branch ruleset that requires pull
  requests lifted for one force-push, then a re-sync of every clone, then the purge request above
  covering the new hash. Until then, put no attribution lines in commit messages or PR bodies;
  GitHub builds the squash message from them.

- [ ] [manual:2026-11-20] **Finish scoped vaults on the live K3s cluster** — the code and tests are in, but
  nothing has run against the cluster. Remaining: enable `secrets-encryption` (needs root, see
  `docs/k3s-scoped-vaults.md`), apply `scope manifest`, run `scope verify`, define the real
  `config/scopes.local.toml`, run `consolidate` (plan, then `--apply`), schedule `scope sync --apply` through
  clockwork, and wire the first writable service to `auto-pass scope return` (return-Secret transport).

## In Progress

## Done
