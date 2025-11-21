# **Comprehensive Attacker Methodology for HackTheBox Machines**

*A generalized methodology distilled from 22+ IppSec HTB walkthroughs*

This document summarizes the **mindset, methodology, reasoning, and tool usage** common across HackTheBox machine walkthroughs. Rather than detailing steps for each box, this describes **how an attacker thinks**, **what decisions they make**, **how they gather information**, and **how they pivot toward exploitation and privilege escalation**.

---

# **1. Attacker Mindset Overview**

A successful attacker has three core habits:

### **1.1 Maintain Strict Information Discipline**

* Assume *nothing*; confirm everything.
* Track environment changes (new ports, credentials, user contexts).
* Constantly update a threat model: *Who am I? What can I see? What can I control?*

### **1.2 Move from Unknown → Known**

The attacker’s job is to convert:

* **Unknown services** → understood technologies
* **Known technologies** → attack surfaces
* **Attack surfaces** → footholds
* **Footholds** → privilege escalation paths

### **1.3 Always Ask “Why is this here?”**

When a system behaves oddly (custom service, unusual file, weird permissions), the attacker uses this question to uncover intent:

* Why is SMB open to guests?
* Why is this API exposing debug info?
* Why is this script world-writable?
* Why did I find cleartext credentials?

Abnormalities lead to exploitation.

---

# **2. High-Level Workflow (Across Almost All HTB Boxes)**

## **Phase 1: Enumeration**

The attacker’s first responsibility is to understand the target.

### **2.1 Network Enumeration**

* **Nmap full scans**

  * `nmap -sC -sV -oA scan target`
  * Full port scan when needed: `nmap -p- -T4 target`

**Why:**

* Detect services, versions, and potential misconfigurations.
* Build a profile: OS type, roles (AD, web server, mail), likely attack vectors.

**Mindset principle:**

> Tools discover services. Humans discover vulnerabilities.

### **2.2 Service Enumeration**

For each open port:

* **Web (80/443)**

  * `gobuster`, `feroxbuster` → enumerate directories
  * `nikto`/manual browsing → fingerprint frameworks
  * Look for login panels, upload areas, API endpoints, debug consoles
  * Analyze cookies, headers, JS for clues

* **SMB**

  * `smbclient -L`
  * Try anonymous access
  * Enumerate shares for configs, credentials, scripts
  * Check permissions (read/write)

* **LDAP/AD Services (Forest, Active, Blackfield)**

  * `ldapsearch`, `enum4linux-ng`, `rpcclient`
  * Enumerate domain users, groups, ACLs
  * Identify attack paths (Kerberoasting, AS-REP roast, LDAP misconfigs)

* **Databases** (MySQL, PostgreSQL, MongoDB)

  * Check for default credentials
  * Enumerate users, tables, stored procedures
  * Search for passwords or file-write functionality

**Why:**
Services reveal both the **technology stack** and **developer intent**, which often hints at the vulnerability.

---

## **Phase 2: Attack Surface Analysis**

### **2.3 Identify Vulnerabilities**

Typical categories:

* **Outdated software (Old WordPress, Tomcat, Jenkins)**
  → search CVEs
* **Misconfigurations (anonymous SMB, writable scripts)**
  → abuse trust relationships
* **Logic flaws (password resets, weak auth)**
  → bypass security
* **Injection opportunities (SQLi, LDAPi, SSTI)**
  → dump DBs, escalate privileges
* **Exposed credentials (config files, logs)**
  → pivot to services

### **2.4 Tool Choices**

Tools are not the goal—they support reasoning.

Common attacker tools:

* Recon: `nmap`, `gobuster`, `feroxbuster`
* Credential attacks: `hydra`, `hashcat`, `john`, `kerbrute`
* AD attacks: `impacket-*`, `evil-winrm`, BloodHound
* Web exploitation: Burp Suite, curl, ffuf
* Reverse shells: `nc`, `socat`, msfvenom (sparingly)
* Post exploitation: `pspy`, `linpeas`, `winPEAS`

**Why these tools?**
Each tool either:

* reduces uncertainty
* extracts hidden data
* or automates noisy tasks

---

## **Phase 3: Initial Foothold**

This is the transition from **remote enumeration** to **code execution or authenticated access**.

### Common foothold patterns across HTB:

* Command injection via web apps
* Unrestricted file upload → web shell
* Leaking credentials → SSH or RDP
* Using AD misconfig: AS-REP Roast, Kerberoast
* Exploiting misconfigured databases (file write, auth bypass)
* Abuse of password reuse across services

**Reasoning approach:**

> If credentials appear anywhere, test them everywhere.

---

## **Phase 4: Post-Exploitation & Privilege Escalation**

### **4.1 Linux PrivEsc Mindset**

Identify:

* **World-writable scripts**, cron jobs → code execution
* **Capabilities** (e.g., python with cap_setuid)
* **SUID binaries** (search: `find / -perm -4000`)
* **Credentials in configs**
* **Docker/LXC misconfig** → breakout
* **NFS root_squash disabled** → root shell
* **Kernel exploits** when environment allows

### **4.2 Windows PrivEsc Mindset**

Focus on:

* **Token impersonation (JuicyPotato/PrintSpoofer)**
* **Bad ACLs** on AD objects
* **Kerberoast / AS-REP Roast**
* **Unquoted Service Paths**
* **Privilege escalation via scheduled tasks**
* **DLL hijacking**
# Methodology — Consolidated Process

This document consolidates the `process/` folder into a single, ordered methodology reference for reconnaissance, exploitation, and privilege escalation. It combines best-practices, checklists and recommended workflows.

## Contents

- Introduction & Approach
- Enumeration Checklist
- Machine Checklist (OSCP-style flow)
- Exploitation Workflow
- Privilege Escalation Methodology
- Notes & References

---

## Introduction & Approach

This section captures the recommended learning path and mindset before attacking HTB/OSCP-style machines. Focus on foundational skills (Linux, Windows, networking), core tools, and a repeatable methodology: Enumeration → Exploitation → Privilege Escalation → Post-Exploitation.

Key learning areas:

- Linux fundamentals (filesystem, permissions, systemctl, common CLI tools, bash scripting)
- Windows fundamentals (PowerShell, services, registry, AD basics)
- Networking basics (TCP/IP, DNS, HTTP/HTTPS)
- Tools: `nmap`, `gobuster`/`ffuf`, Burp Suite, `sqlmap`, `netcat`
- Mindset: patience, curiosity, systematic note-taking

Recommended progression before intermediate/advanced boxes:

1. PortSwigger Academy — web fundamentals
2. TryHackMe — Jr PenTester pathway
3. OverTheWire (Bandit) — Linux CLI practice
4. HTB Starting Point → easy HTB boxes → medium/hard boxes

---

## Enumeration Checklist

Systematic reconnaissance and service enumeration for every machine.

### Phase 1: Host Discovery

- Ping sweep (if applicable)
- Identify target IP/hostname
- Document target OS from early probes

### Phase 2: Port Scanning

- Initial quick scan: `nmap -p- --open -T4 <target>`
- Service/version detection: `nmap -sV -sC -p <ports> -oN nmap-detailed.txt <target>`

### Phase 3: HTTP/HTTPS Enumeration

- Manual inspection (browser)
- Directory fuzzing: `gobuster`, `ffuf`, `dirsearch`
- Check `robots.txt`, `sitemap.xml`, JS files for endpoints
- Intercept traffic with Burp Suite and map parameters/endpoints

### Phase 4: SMB / FTP / DB / SSH Enumeration

- SMB: `smbclient -L //<IP>/`, `enum4linux`
- FTP: test anonymous login
- DB: attempt connections, check default creds
- SSH: banner/version checks

### Phase 5: Credential Harvesting & Vulnerability Mapping

- Search files/configs for credentials (LFI, uploads, repo files)
- Cross-reference versions with Exploit-DB / searchsploit
- Document all findings and prepare for exploitation

---

## HackTheBox Machine Checklist (OSCP-style)

Use this flow for every box — start to finish.

### Pre-Engagement

- Create machine folder and notes file
- Start VPN and confirm connectivity
- Add discovered hostnames to `/etc/hosts` as needed

### Initial Recon / Enumeration

- Run `nmap` scans and record open ports & services
- Use `gobuster`/`ffuf` for web directories
- Note any admin panels, upload endpoints, or API routes

### Identify & Exploit Foothold

- Prioritize vectors (LFI, SQLi, file upload, RCE, auth bypass)
- Validate vulnerabilities manually before automating
- Host payloads and catch reverse shells (nc, socat)
- Stabilize shells and gather initial post-exploitation info

### Post-Exploitation

- Run initial enumeration (`id`, `sudo -l`, `uname -a`, `find` for SUID)
- Search for credentials, cron jobs, writable scripts, and capabilities

### Flags & Documentation

- Capture `user.txt` and `root.txt` (or platform equivalents)
- Record full exploitation chain, commands, and evidence

---

## Exploitation Workflow

A structured approach to vulnerability testing and exploitation.

### Pre‑Exploitation

- Review enumeration and prioritize by likely impact & feasibility
- Prepare tools and shell handlers

### Vulnerability Validation

- Confirm POC, understand the input → processing → output chain
- Map what access level an exploit provides (user, service, system)

### Web Application Exploits (common)

- SQL Injection (manual tests + `sqlmap`)
- RCE via file upload, command injection, SSTI, or deserialization
- LFI leading to RCE through log poisoning or wrappers
- Unprotected functionality and auth bypasses

### System/Network Exploits

- Research CVEs with `searchsploit` and adapt PoCs
- Test misconfigurations (default creds, open shares, exposed management)

### Shell Acquisition & Stabilization

- Establish reverse/bind shell, stabilize TTY, check execution context

### Post‑Exploit Enumeration

- Enumerate user, groups, services, mounted filesystems, and network
- Locate sensitive files and escalation vectors

---

## Privilege Escalation Methodology

Techniques for escalating from an initial shell to root/SYSTEM.

### Linux Privesc (ordered checklist)

1. Information gathering: `whoami`, `id`, `sudo -l`, kernel version, container checks
2. SUID/GUID binaries: `find / -perm -4000 2>/dev/null`
3. Writable directories & scripts: look for scripts executed by root or cron
4. Sudo misconfigurations: test `sudo -l` results (wildcards, binaries that allow shell escapes)
5. Cron jobs: inspect `/etc/crontab`, `/etc/cron.d/*`, user crons
6. Capabilities: `getcap -r / 2>/dev/null`
7. Kernel exploits (last resort): research CVEs for local privilege escalation
8. Credential hunting: history files, config files, SSH keys

### Windows Privesc (ordered checklist)

1. Information gathering: `whoami /priv`, `systeminfo`, check UAC and patches
2. Service enumeration: unquoted service paths, writable service directories
3. Token abuse: SeImpersonatePrivilege and impersonation tools
4. Registry and file permissions: writable HKLM, scripts, installers
5. Scheduled tasks: check tasks running as SYSTEM or admin
6. Known CVEs & service exploits

---

## Notes, Tools & Resources

Helpful tools referenced throughout the methodology:

- `nmap`, `gobuster`/`ffuf`, `burp suite`, `sqlmap`, `netcat`, `searchsploit`
- Enumeration scripts: `linPEAS`, `winPEAS`, `LinEnum`
- Privilege escalation resources: GTFOBins, HackTricks, Exploit-DB

Guidelines

- Keep methodical notes and capture exact commands and outputs
- Prefer manual validation over blind automation
- When merging notes or archives, keep section headers like `Merged from <path>` for traceability

---

*This consolidated methodology was generated by combining the individual files in the `process/` folder. If you'd like a different section order, more detail in any area, or a TOC with internal links, tell me and I'll refine it.*
