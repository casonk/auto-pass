# LESSONSLEARNED.md

Tracked durable lessons for `auto-pass`.
Unlike `CHATHISTORY.md`, this file should keep only reusable lessons that should change how future sessions work in this repo.

## How To Use

- Read this file after `AGENTS.md` and before `CHATHISTORY.md` when resuming work.
- Add lessons that generalize beyond a single session.
- Keep entries concise and action-oriented.
- Do not use this file for transient status updates or full session logs.

## Lessons

- Document secret-wrapper utilities around three seams: env/profile resolution,
  secret-context resolution, and subprocess execution.
- Show read and write paths separately when create-on-miss behavior is a real
  branch of the implementation.
- Keep local cache files and local env files explicit in the architecture, but
  never inspect or record their secret contents.
