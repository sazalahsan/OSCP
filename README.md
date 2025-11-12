# OSCP Notes

This folder is a personal workspace to track OSCP study materials, lab notes, cheatsheets, and artifacts.

Top-level structure

- labs/ — per-machine lab notes and writeups
- cheatsheets/ — quick command references (nmap, smb, linux privilege escalation, Windows, etc.)
- templates/ — markdown templates for notes and labs
- resources/ — links, PDFs, blogs, reference material
- scripts/ — helper scripts (setup, aliases, screenshot helpers)
- reports/ — exam/report drafts
- tools/ — tools you use or scripts that help
- web/ — web-app specific notes, Burp rules, WAF bypasses
- priv-esc/ — privilege escalation technique notes
- enumeration/ — enumeration patterns and outputs
- post-exploitation/ — post-exploitation notes
- windows/, linux/, buffers/ — OS-specific notes

Naming conventions

- Individual lab notes: `labs/<date>-<target>-<short-name>.md` or `labs/<target>.md`
- Use `YYYY-MM-DD` date prefix for chronological ordering when relevant
- Keep commands in fenced code blocks and paste outputs when useful

How to use

- Copy files from `templates/` when creating new machine writeups or lesson notes.
- Keep the cheatsheet updated with one-liners you use frequently.
- Use `scripts/setup.sh` to install helper tools and set aliases (optional).

License/Privacy

Keep any exam-sensitive material private. Do not share active lab/exam outputs publicly if they are disallowed by the exam rules.
