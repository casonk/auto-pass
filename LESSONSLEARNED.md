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
