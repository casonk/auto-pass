# BACKLOG.md

Portfolio backlog for this repository. Pending items are candidates for execution —
manually or via crew-chief. Entries sourced from archility audit are tagged
`[archility:YYYY-MM-DD]`; manual entries use `[manual:YYYY-MM-DD]`.

The archility twice-weekly job populates this file automatically via `archility audit --write-backlog`.
To execute a backlog item with crew-chief: `crew-chief agent "Work on item: <item text>"`.
Mark items `[x]` when complete and move them to Done.

## Pending

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

## In Progress

## Done
