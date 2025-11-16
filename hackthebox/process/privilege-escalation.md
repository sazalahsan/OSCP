# Privilege Escalation Methodology

Techniques and checklist for escalating from initial shell to root/SYSTEM on HackTheBox machines.

## Linux Privilege Escalation

### Phase 1: Information Gathering

- [ ] Current user: `whoami`, `id`
- [ ] User groups: `groups`
- [ ] Sudoers file: `sudo -l` (with/without password)
- [ ] System info: `uname -a`, `cat /etc/os-release`
- [ ] Kernel version (search for exploits)
- [ ] Check if running in container: `cat /proc/1/cgroup`, `/.dockerenv`

### Phase 2: SUID/GUID Binaries

- [ ] Find SUID binaries: `find / -perm -4000 2>/dev/null`
- [ ] Find GUID binaries: `find / -perm -2000 2>/dev/null`
- [ ] Check if common binaries are SUID (cp, find, tar, etc.)
- [ ] Test for exploitation:
  - Unbounded command execution: `find . -exec /bin/sh \;`
  - Library path manipulation: `LD_LIBRARY_PATH`, `LD_PRELOAD`
  - Wildcard exploitation (tar, rsync with `*`)

### Phase 3: Writable Directories & Files

- [ ] World-writable directories: `find / -type d -perm -002 2>/dev/null`
- [ ] Check `/tmp`, `/var/tmp`, `/dev/shm` for write permissions
- [ ] Identify scripts/binaries in writable locations that run as higher privilege
- [ ] Replace or modify files to execute malicious code

### Phase 4: Sudo Abuse

- [ ] `sudo -l` – check what can be run without password
- [ ] Common targets:
  - `sudo chmod` – modify permissions
  - `sudo cp` – copy files (overwrite root files)
  - `sudo find` / `sudo tar` – command injection via `-exec`
  - `sudo python/ruby/perl` – run arbitrary code
  - `sudo less/more/vi` – shell escape (e.g., `:!sh`)
  - `sudo *` (all commands) – immediate root
- [ ] Test wildcard sudo rules: `sudo /path/to/*` might allow arbitrary path

### Phase 5: Cron Jobs

- [ ] Check system cron: `cat /etc/crontab`, `/etc/cron.d/*`
- [ ] Check user crons: `crontab -l`, `/var/spool/cron/crontabs/*` (root)
- [ ] Identify high-privilege cron jobs
- [ ] Look for:
  - Scripts in writable directories
  - Wildcard usage in commands
  - Predictable file paths (no full path specified)
- [ ] Exploitation: create malicious script in cron path or modify existing cron script

### Phase 6: Capability Abuse

- [ ] Check file capabilities: `getcap -r / 2>/dev/null`
- [ ] Common dangerous capabilities:
  - `cap_setuid` – set UID to 0 (root)
  - `cap_dac_override` – bypass file permissions
  - `cap_sys_admin` – namespace escape (containers)
- [ ] Example: `/bin/ping` with `cap_net_raw` can be chained with other exploits

### Phase 7: Kernel Exploits

- [ ] Identify kernel version: `uname -r`
- [ ] Search for known CVEs: `searchsploit linux kernel <version>`
- [ ] Common exploits:
  - CVE-2016-5195 (Dirty COW) – write to read-only files
  - CVE-2021-3493 (OverlayFS) – privilege escalation
  - CVE-2019-14287 (Sudo) – bypass sudo restrictions
- [ ] Compile and run exploit (if available/allowed)
- [ ] Requires caution: may crash system or cause stability issues

### Phase 8: Password/Credential Hunting

- [ ] Search for password files: `grep -r "password" /home /etc /var/www 2>/dev/null`
- [ ] Check shell history: `cat ~/.bash_history`, `~/.zsh_history`
- [ ] Look for SSH keys: `find / -name "id_rsa" 2>/dev/null`
- [ ] Check for .aws, .ssh, .config directories
- [ ] Read config files in `/etc` (mysql, apache, nginx, etc.)

### Phase 9: NFS Shares

- [ ] Check NFS exports: `showmount -e <target>` (from attacker)
- [ ] Mount NFS shares: `mount -t nfs <target>:/path /mnt/local`
- [ ] Check for root_squash bypass or missing root_squash
- [ ] Create SUID binary in NFS and execute as target user

### Phase 10: Container Escape (if in container)

- [ ] Detect container: `cat /.dockerenv`, cgroup checks
- [ ] Check for mounted host filesystem
- [ ] Look for privileged capabilities or insecure Docker socket
- [ ] Escape via cgroup, namespace, or privileged container configurations

## Windows Privilege Escalation

### Phase 1: Information Gathering

- [ ] Current user: `whoami`, `whoami /priv`
- [ ] User groups: `net user %username%`, `whoami /groups`
- [ ] System info: `systeminfo`, `wmic os get caption`
- [ ] Check UAC: `wmic UAC Get /Format:list`
- [ ] Check for patches: `wmic qfe list brief full` or `Get-HotFix`

### Phase 2: Service Exploitation

- [ ] List services: `wmic service list brief`, `sc query`
- [ ] Check service paths for unquoted path vulnerability: `wmic service get name,pathname | findstr /V "C:\Windows"`
- [ ] Test write permissions to service directories
- [ ] Restart service (if possible) to execute malicious binary

### Phase 3: Token Abuse (Impersonation)

- [ ] List available tokens: `whoami /priv`
- [ ] Look for SeImpersonate, SeAssignPrimaryToken
- [ ] Use tools like Incognito or PrintSpoofer to impersonate SYSTEM

### Phase 4: Registry/File Permissions

- [ ] Check registry permissions (especially HKLM)
- [ ] Check file permissions on sensitive locations (Program Files, Windows, etc.)
- [ ] Modify registry or files if writable to achieve execution

### Phase 5: Scheduled Tasks

- [ ] List tasks: `tasklist /FI "USERNAME eq SYSTEM"`
- [ ] Check task details: `Get-ScheduledTask`, `schtasks /query`
- [ ] Look for tasks that run as SYSTEM or admin with editable scripts/binaries

### Phase 6: Known CVE/Exploit

- [ ] Kernel exploits (same as Linux, but for Windows kernel)
- [ ] Service-specific exploits (Windows services often have escalation paths)
- [ ] Search: `wmic qfe list` → compare against known CVEs

## Post-Privilege Escalation

- [ ] Confirm root/SYSTEM access: `id`, `whoami /priv`
- [ ] Capture root/system flag
- [ ] Document the full chain
- [ ] Consider persistence (if lab allows/requires)

## Tools & Resources

- **LinEnum.sh** – Automated Linux enumeration
- **PEASS (winPEAS/linPEAS)** – Privilege escalation assessment scripts
- **searchsploit** – Local exploit database
- **GTFOBins** – SUID/sudo/capability escape database
- **HackTricks** – Privilege escalation techniques
- **Exploit-DB** – Public exploit collection

## Common Pitfalls

- Not checking `sudo -l` first (often the quickest vector)
- Overlooking writable directories that run high-privilege code
- Ignoring cron jobs and scheduled tasks
- Not researching kernel exploits if no obvious vector exists
- Assuming services/binaries are secure without testing

## Notes

- Privilege escalation is often a chain of small vulnerabilities; enumerate thoroughly.
- Document the full chain: how each step leads to the next.
- Test local exploits carefully; some may destabilize the system.
- Kernel exploits should be last resort due to risk.
