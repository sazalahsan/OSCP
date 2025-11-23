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

# Attacker Methodology — Cleaned & Organized

This file consolidates the `process/` folder into a single, non-redundant reference. Content is ordered from basics → intermediate → advanced. Similar topics are grouped together and repeated items removed.

## Contents

- 1. Introduction & Prerequisites
- 2. Pre-engagement / Setup
- 3. Enumeration (host → service → application)
- 4. Exploitation workflow
- 5. Post-exploitation & stabilization
- 6. Privilege escalation (Linux then Windows)
- 7. Tools & resources
- 8. Notes, documentation & ethics

---

## 1. Introduction & Prerequisites

Goal: establish a repeatable approach to attacking lab/CTF machines so removing the original per-topic files does not lose important concepts.

Essential foundations:
- Linux basics: filesystem, users, services, package managers, shell scripting
- Windows basics: PowerShell, services, registry, scheduled tasks
- Networking: TCP/UDP, DNS, HTTP/HTTPS, basic routing/subnets
- Development scripting: Python and shell scripting for small tools/PoCs

Recommended training order:
1. PortSwigger Web Academy (web fundamentals)
2. OverTheWire (Bandit) for CLI skills
3. TryHackMe / VulnHub practical boxes
4. HTB Starting Point → Easy → Medium → Hard

---

## 2. Pre-engagement / Setup

Checklist before attacking a target:
- Create project folder and notes file for the machine
- Ensure VPN connectivity and target reachability
- Add discovered hostnames to `/etc/hosts` if needed
- Prepare listeners and temporary hosts (nc, socat, python http.server)

Quick commands (examples):

```bash
mkdir -p ~/labs/<machine>
cd ~/labs/<machine>
openvpn ~/keys/htb.ovpn
nc -lvnp 9001
python3 -m http.server 8000
```

---

## 3. Enumeration (host → service → application)

Principle: start broad, then focus. Record everything.

### 3.1 Host discovery
- Confirm host is up (ping / nmap ping) and note any hostnames

### 3.2 Port scanning
- Initial fast scan: `nmap -p- -T4 --min-rate 1000 <target>`
- Service detection: `nmap -sV -sC -p <ports> -oN nmap-service.txt <target>`

### 3.3 Service-specific enumeration (per open port)
- Web (80/443/8080…): browse manually, intercept with Burp, enumerate directories/endpoints (`gobuster`, `ffuf`), inspect JS for endpoints/credentials
- SMB (445/139): `smbclient -L //<IP>/`, try anonymous, enumerate shares, download configs
- Databases: attempt connections (MySQL, PostgreSQL, Mongo, MSSQL), test default credentials, search for file write or credential storage
- SSH/WinRM/RDP: banner/version checks; save for later credential testing

### 3.4 Automated and manual helpers
- Use both manual inspection and quick automated checks: `nikto`, `searchsploit`, `enum4linux`, `ffuf`
- Keep lists of endpoints, parameters, and interesting responses in your notes

### 3.5 Credential harvesting
- Search discovered files, backups, config files, JS, and logs for credentials
- Try found credentials across all services (password reuse is common)

---

## 4. Exploitation workflow

### 4.1 Prioritize
- Rank candidates by impact, ease, and risk (e.g., RCE > info disclosure > fingerprinting)

### 4.2 Validate first
- Reproduce a minimal POC manually before running automated exploit code

### 4.3 Web exploitation categories (common)
- Injection: SQLi (extract DB), LDAPi, command injection
- File handling: LFI, RFI, path traversal, file upload
- Server-side flaws: SSTI, deserialization, insecure deserialization
- Unprotected functionality: admin panels, API endpoints without auth

### 4.4 System / network exploitation
- Look up versions in Exploit-DB / searchsploit and adapt PoC code
- Test for default creds, open shares, and exposed management interfaces

### 4.5 Shell acquisition & stabilization
- Acquire a shell (reverse/bind), then stabilize (pty), gather context (`whoami`, `id`, `pwd`)

Example stabilization:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# then in your terminal:
# CTRL-Z; stty raw -echo; fg; export TERM=xterm
```

### 4.6 Documentation during exploitation
- Record exact payloads, commands, outputs, and any artifacts used

---

## 5. Post-exploitation & stabilization

### 5.1 Initial enumeration (once a shell is available)
- User & groups: `whoami`, `id`, `groups`
- System: `uname -a`, `cat /etc/os-release`
- Sudo: `sudo -l`
- Running processes & network: `ps aux`, `netstat -tunlp` or `ss -tunlp`

### 5.2 Search for immediate escalators
- Config files, credentials, SSH keys, backups, world-writable scripts
- Cron jobs and systemd timers that run as root

### 5.3 Lateral movement (where applicable)
- If credentials or tokens are found, attempt internal pivots (SSH, SMB, RPC)
- For AD environments, enumerate domain users/groups and use BloodHound-style reasoning

### 5.4 Persistence & cleanup (labs only when allowed)
- Prefer ephemeral access for CTFs; avoid persistence unless required
- Clean temporary files and payloads if you're asked to by lab rules

---

## 6. Privilege escalation (ordered checklists)

Principle: escalate using the least destructive, highest-leverage method first. Document every step.

### 6.1 Linux checklist (order to try)
1. `whoami`, `id`, `sudo -l` (check sudo rules)
2. Search for credentials in home, webroot, config files: `grep -R "password" /var/www /home /etc 2>/dev/null`
3. SUID binaries: `find / -perm -4000 -type f 2>/dev/null`
4. Writable files/scripts run by root (cron, /etc/cron.*, systemd unit files)
5. World-writable directories and PATH issues
6. File capabilities: `getcap -r / 2>/dev/null`
7. Docker / container checks: `cat /.dockerenv`, `ls -la /var/run/docker.sock`
8. Kernel exploits (last resort) — match kernel version to public CVEs carefully

### 6.2 Windows checklist (order to try)
1. `whoami /priv`, `systeminfo`, check patch level
2. Service paths (unquoted service path) and writable service binaries
3. Scheduled tasks that run as SYSTEM or admin
4. Weak ACLs on files or registry keys
5. Token impersonation (SeImpersonatePrivilege) and token theft
6. AD-specific: AS-REP roast, Kerberoast, weak group policies

---

### 7. Tools & resources (authoritative list)

Scanning & enumeration:
- `nmap`, `masscan`, `enum4linux`, `ss`, `netstat`

Web testing:
- Burp Suite, `ffuf`, `gobuster`, `nikto`, `sqlmap`

Exploitation & post-exploit:
- `nc`, `socat`, `msfvenom` (sparingly), custom Python scripts
- Enumeration scripts: `linPEAS`, `winPEAS`, `LinEnum`

AD & Windows tools:
- Impacket suite, `evil-winrm`, BloodHound, `kerbrute`, `hashcat`

Reference resources:
- Exploit-DB / searchsploit, GTFOBins, HackTricks, OWASP, PacketNotes

---

## 8. Notes, documentation & ethics

- Keep consistent notes: commands, outputs, nmap results, screenshots where useful
- Use source markers when merging content (e.g., `Merged from: checklist.md`) — earlier merges included these markers in history
- Prefer manual validation over blindly running exploits
- Follow lab/CTF rules: do not attempt persistence or destructive actions on shared infrastructure unless allowed

---

If you want, I can:
- Add an internal TOC with anchors
- Run a dedupe pass to remove near-duplicate lines (needs review)
- Export this as a printable checklist or Obsidian-friendly note

<!-- consolidated from process/*.md -->

5.3 Lateral movement (where applicable)
- If credentials or tokens are found, attempt internal pivots (SSH, SMB, RPC)
- For AD environments, enumerate domain users/groups and use BloodHound-style reasoning

5.4 Persistence & cleanup (labs only when allowed)
- Prefer ephemeral access for CTFs; avoid persistence unless required
- Clean temporary files and payloads if you're asked to by lab rules

---

## 6. Privilege escalation (ordered checklists)

Principle: escalate using the least destructive, highest-leverage method first. Document every step.

6.1 Linux checklist (order to try)
1. `whoami`, `id`, `sudo -l` (check sudo rules)
2. Search for credentials in home, webroot, config files: `grep -R "password" /var/www /home /etc 2>/dev/null`
3. SUID binaries: `find / -perm -4000 -type f 2>/dev/null`
4. Writable files/scripts run by root (cron, /etc/cron.*, systemd unit files)
5. World-writable directories and PATH issues
6. File capabilities: `getcap -r / 2>/dev/null`
7. Docker / container checks: `cat /.dockerenv`, `ls -la /var/run/docker.sock`
8. Kernel exploits (last resort) — match kernel version to public CVEs carefully

6.2 Windows checklist (order to try)
1. `whoami /priv`, `systeminfo`, check patch level
2. Service paths (unquoted service path) and writable service binaries
3. Scheduled tasks that run as SYSTEM or admin
4. Weak ACLs on files or registry keys
5. Token impersonation (SeImpersonatePrivilege) and token theft
6. AD-specific: AS-REP roast, Kerberoast, weak group policies

---

## 7. Tools & resources (authoritative list)

Scanning & enumeration:
- `nmap`, `masscan`, `enum4linux`, `ss`, `netstat`

Web testing:
- Burp Suite, `ffuf`, `gobuster`, `nikto`, `sqlmap`

Exploitation & post-exploit:
- `nc`, `socat`, `msfvenom` (sparingly), custom Python scripts
- Enumeration scripts: `linPEAS`, `winPEAS`, `LinEnum`

AD & Windows tools:
- Impacket suite, `evil-winrm`, BloodHound, `kerbrute`, `hashcat`

Reference resources:
- Exploit-DB / searchsploit, GTFOBins, HackTricks, OWASP, PacketNotes

---

## 8. Notes, documentation & ethics

- Keep consistent notes: commands, outputs, nmap results, screenshots where useful
- Use source markers when merging content (e.g., `Merged from: checklist.md`) — I have preserved these in prior commits
- Prefer manual validation over blindly running exploits
- Follow lab/CTF rules: do not attempt persistence or destructive actions on shared infrastructure unless allowed

---

If you want, I can:
- Add an internal TOC with anchors
- Run a dedupe pass to remove near-duplicate lines (needs review)
- Export this as a printable checklist or Obsidian-friendly note

<!-- consolidated from process/*.md -->

``` 
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
