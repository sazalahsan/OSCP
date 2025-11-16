# Approach: What to Learn Before Starting HackTheBox

This is a clear, structured roadmap of what you should learn before starting HackTheBox (HTB) machines — especially if your goal is OSCP or structured pentesting skill growth.

---

## ✔️ 1. Core Technical Foundations

These are non-negotiable basics.

### Linux fundamentals

- File system navigation & permissions
- System services (`systemctl`, networking tools)
- Common CLI utilities: `grep`, `sed`, `awk`, `find`, `curl`, `wget`, `nc`
- Bash scripting basics
- Package management (`apt`, `yum`)

### Windows fundamentals

- Command Prompt & PowerShell basics
- File system & permissions
- Understanding of services, registry, scheduled tasks
- Basic Active Directory concepts (users, groups, domains)

### Networking fundamentals

- TCP/IP, ports, protocols
- DNS, HTTP/HTTPS
- Subnetting & routing (just enough to know what you’re seeing in scans)
- Firewall behavior basics

---

## ✔️ 2. Pentesting Methodology (OSCP-style)

Before touching machines, learn the process.

### Enumeration → Exploitation → Privilege Escalation → Post-Exploitation

- How to enumerate thoroughly
- How to keep notes
- How to pivot when something doesn’t work
- How to escalate in both Linux & Windows environments

---

## ✔️ 3. Tools You Must Be Comfortable With

These tools appear in nearly every HTB machine.

### Scanning & Enumeration

- `nmap` (aggressive scan, scripts, service detection)
- `nikto`, `gobuster`/`ffuf`, `dirsearch`

### Web exploitation basics

- Understanding HTTP requests
- Burp Suite (proxy, repeater, intruder)
- Manual testing of parameters

### Exploitation

- Metasploit (optional for OSCP, useful for HTB)
- `msfvenom` payloads
- Netcat / Socat / SSH tricks
- Reverse shell stabilisation (pty, `stty`, python)

### Scripting

- Using Python, bash, or PowerShell to automate small tasks
- Writing simple PoC scripts

---

## ✔️ 4. Common Vulnerabilities You Should Understand

HTB machines heavily rely on these categories.

### Web vulns

- Command injection
- File uploads
- LFI/RFI
- SQLi
- XSS (mostly for foothold)
- SSRF
- Path traversal
- Authentication bypass techniques

### System vulns

- SUID binaries
- Cron jobs
- PATH hijacking
- Capabilities
- Kernel exploits (less common now)

### Windows vulns

- Misconfigured services
- Privilege escalation shortcuts like:
  - Unquoted service paths
  - Weak permissions
  - UAC bypass
  - Token abuse
  - Exploitable scheduled tasks
- Basic AD privesc:
  - Kerberoasting
  - AS-REP roasting
  - Pass-the-Hash
  - Bloodhound enumeration

---

## ✔️ 5. Exploit Research Skills

Before attacking real HTB machines, you should know how to:

- Search Exploit-DB and adapt exploits
- Patch broken PoC scripts
- Modify Python2 → Python3
- Understand CVE write-ups well enough to replicate manually

---

## ✔️ 6. Privilege Escalation Knowledge (Huge part of HTB)

### Linux Privesc

- SUID enumeration
- `sudo` misconfigurations
- Crontab jobs
- Capabilities (`getcap -r /`)
- PATH hijacking
- File permissions misconfigurations
- Docker/LXC escapes

### Windows Privesc

- `winPEAS` / `seatbelt`
- Privileges (SeImpersonatePrivilege, etc.)
- Service permissions (`sc qc`, `accesschk`)
- Registry permissions
- PowerShell privesc methods
- Basic AD privesc path-building

---

## ✔️ 7. Note-Taking & Documentation

Learn one note system and stick to it:

- Obsidian
- CherryTree
- Notion
- OneNote
- Markdown + Sublime

Record:

- Each enumeration step
- Commands used
- Service versions
- Possible exploitation vectors
- Credentials found
- Privilege escalation findings

Good notes = faster rooting in future machines.

---

## ✔️ 8. Mental Approach to CTF/Pentesting

HTB machines require:

- Patience
- Curiosity
- Ability to research effectively
- Willingness to try multiple approaches
- Logical elimination of dead ends

Many people quit early because they expect HTB to be like a textbook — it is not. It’s puzzle-based pentesting.

---

## ✔️ 9. Early Training Before HTB

These platforms are perfect warm-ups:

### Beginner Platforms

- PortSwigger Web Academy
- TryHackMe (complete “Jr Penetration Tester” and “Offensive Pentesting”)
- VulnHub “OSCP-style” machines
- OverTheWire Bandit (Linux CLI training)

Once you’re comfortable, move to:

### HTB Starting Point + Tier 0/1

This is where things start to feel like real OSCP exercises.

---

## ✔️ 10. Recommended order before doing HTB intermediate/advanced boxes

1. PortSwigger → Learn core web vulns
2. TryHackMe → Do Jr PenTester pathway
3. OverTheWire → Do Bandit
4. HTB Starting Point → Very easy machines
5. HTB Easy machines → Build confidence
6. HTB Medium/Hard machines → OSCP-level challenge

---

## Extras — Options I can prepare for you

If you want, I can also create:

- A personalized study roadmap based on your current level
- A checklist you follow during every HTB machine
- A daily practice plan leading up to OSCP

Tell me which one you want next and I’ll generate it.
