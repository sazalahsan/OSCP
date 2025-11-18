# OSCP Notes

Canonical, single-file-per-topic notes and study materials for OSCP/HTB-style learning.

Repository layout (current)

- `notes/` — Canonical topic files (one merged file per topic). Examples: `notes/sqli.md`, `notes/path-traversal.md`, `notes/ssrf.md`, etc.
- `process/` — Methodology and playbooks (enumeration, exploitation, privilege escalation, checklists).
- `templates/` — Reusable Markdown templates: `topic-template.md`, `lab-template.md`, `note-template.md`.
- `tools/` — Utility scripts, payload lists, wordlists, and helper resources used during testing.
- `.scripts/` — Workspace maintenance scripts (merge/dedupe/cleanup helpers). These are for convenience and can be reviewed before running.
- `README.md`, `SUMMARY.md` — High-level navigation and table-of-contents for study flow.

What changed

- The workspace now uses a single canonical file per topic under `notes/`. Duplicate copies (previously in `notes/canonical/`, `archive/`, or `labs/`) were merged into these canonical files and removed to reduce clutter.
- Archived content was merged into the canonical files under clearly labelled "Merged from ..." sections. If you prefer a different organization (move labs into a `labs/` folder again), revert or re-run the `.scripts/merge_and_cleanup.sh` script.

How to create new content

- Use the templates in `templates/`:
  - Copy `templates/topic-template.md` → `notes/<topic>.md` and edit.
  - Use `templates/lab-template.md` for machine writeups if you prefer separate lab files.
- Keep a single canonical topic file per subject — append lab writeups, examples, and cheats under clear subsections.

Scripts and maintenance

- `.scripts/dedupe_notes.sh` — removes exact duplicate chunks and normalizes heading levels across `notes/*.md`.
- `.scripts/merge_sections.sh` — merges repeated H2 sections by title and preserves unique content.
- `.scripts/merge_and_cleanup.sh` — used earlier to merge archived copies and remove archive folders. Inspect before running if re-used.

Version control

- I recommend committing changes locally and reviewing diffs before pushing to any remote. This workspace contains sensitive notes — do not push exam-licensed material if prohibited.

Guidelines

- Keep each topic file readable: a short overview, detection checklist, tools/payloads, commands, and a "Lab / Examples" section.
- Use fenced code blocks for commands and HTTP requests.
- When merging external notes, add a small header like `## Merged from <path>` so you can identify the source.

If you'd like, I can:

- Create a one-line `SUMMARY.md` TOC that links to all `notes/*.md` files.
- Create a local git commit for the cleanup and merging (I will not push without your approval).

