# HackTheBox Lab Repository

A structured system for solving HackTheBox machines, documenting writeups, and building reusable tools and processes.

## Folder Structure

```
hackthebox/
├── README.md                 # This file
├── process/                  # Methodology & process documentation
│   ├── enumeration.md       # Host discovery & enumeration checklist
│   ├── exploitation.md      # Exploitation workflow
│   ├── privilege-escalation.md # PrivEsc techniques & methodology
│   └── template.md          # Writeup template (copy for each box)
├── tools/                    # Custom scripts & tool wrappers
│   ├── enum.sh              # Automated enumeration wrapper
│   ├── exploit.sh           # Exploitation helper
│   └── payloads.txt         # Common payload lists
└── writeups/                # Lab solution writeups (one folder per box)
    └── template/            # Example writeup structure
        ├── README.md        # Box overview & summary
        ├── enumeration.md   # Recon & scanning results
        ├── exploitation.md  # Vulnerability discovery & exploitation
        ├── privilege-escalation.md # PrivEsc chain
        └── notes.md         # Additional findings & post-exploitation
```

## Quick Start

1. **Solve a box** on HackTheBox.
2. **Copy the template** from `process/template.md` or duplicate an existing writeup folder.
3. **Document your process** following the enumeration → exploitation → privesc flow.
4. **Reference tools** from the `tools/` folder and update payloads as you discover new techniques.
5. **Commit & push** your writeup to GitHub.

## Key Documents

- **process/enumeration.md** – Systematic recon & scanning checklist
- **process/exploitation.md** – Vulnerability testing & exploitation workflow
- **process/privilege-escalation.md** – PrivEsc techniques & detection methods
- **process/template.md** – Markdown template for new writeups

## Tools

- **tools/enum.sh** – Wrapper to automate common enumeration tasks
- **tools/exploit.sh** – Helper for exploitation workflows
- **tools/payloads.txt** – Curated payload lists for testing

## Naming Convention for Writeups

Create a folder under `writeups/` named after the machine (lowercase, dashes for spaces):

```
writeups/machine-name/
  ├── README.md              # Box info & high-level summary
  ├── enumeration.md         # Recon results
  ├── exploitation.md        # Vulnerability exploitation
  ├── privilege-escalation.md # PrivEsc chain
  └── notes.md               # Additional findings
```

Example: `writeups/blue/`, `writeups/legacy/`, `writeups/lame/`, etc.

## Next Steps

1. Review the process documents to understand the methodology.
2. Use the template to structure your first writeup.
3. Iterate and refine based on each box you solve.
