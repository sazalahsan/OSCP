# ✅ HackTheBox Machine Checklist (OSCP-style)

**Use this exact flow for every box — easy, medium, hard.**

---

# 1️⃣ Pre-Engagement Setup

- [ ] Create a machine folder: `mkdir HTB/<machine>`
- [ ] Start a notes file (Obsidian/Markdown/CherryTree)
- [ ] Start machine VPN connection (`openvpn <file>.ovpn`)
- [ ] Ping target → confirm active
- [ ] Add target to `/etc/hosts` if hostname discovered later

---

# 2️⃣ Initial Recon / Enumeration

### 🔍 **Nmap Scan**

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

# 3️⃣ Service Enumeration (per port)

### 🌐 **If Web ports (80/443/etc)**

- [ ] Visit site manually and note functionality
- [ ] Use **gobuster/ffuf** for directory brute force
- [ ] Look for hidden paths
- [ ] Check robots.txt, sitemap.xml
- [ ] Intercept traffic with Burp Suite
- [ ] Enumerate parameters (use Param Miner if allowed)
- [ ] Run nikto if relevant (`nikto -h <IP>`)

### 📁 **If SMB (445/139)**

- [ ] `smbclient -L //<IP>/`
- [ ] Try null or guest logins
- [ ] Enumerate shares

### 🗂 **If FTP**

- [ ] Try anonymous login
- [ ] Mirror files if allowed

### 📡 **If SSH/WinRM/RDP**

- [ ] Look for weak creds
- [ ] Note banner versions
- [ ] Prepare for bruteforcing only if ethically permitted (HTB usually allows)

### 🧬 **If Database Ports**

- [ ] MySQL → test root/no password
- [ ] PostgreSQL → test default creds
- [ ] MongoDB → check for unauth access
- [ ] Redis → test `redis-cli -h <IP>`

---

# 4️⃣ Identify & Exploit Foothold

### 🔎 Search for vulnerabilities

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

### 🧪 Test manually

- [ ] Parameter tampering (via Burp)
- [ ] Try basic payloads
- [ ] Upload tests (double extension, bypasses)
- [ ] URL manipulation

### 🛠 Exploitation

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

# 5️⃣ Post-Exploitation Enumeration (Once Foothold Gained)

### 🐧 Linux

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

### 🪟 Windows

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

# 6️⃣ Privilege Escalation

### Linux Privesc Vectors

- [ ] SUID binaries
- [ ] Misconfigured sudo (`sudo -l`)
- [ ] Cron jobs or scripts writable
- [ ] PATH hijacking
- [ ] Capabilities
- [ ] Exploitable services
- [ ] Docker/LXC breakout
- [ ] Kernel exploit (rare but possible on HTB)

### Windows Privesc Vectors

- [ ] Unquoted service paths
- [ ] Weak service binaries permissions
- [ ] Modifiable registry autoruns
- [ ] Token impersonation (SeImpersonatePrivilege)
- [ ] Scheduled tasks
- [ ] Stored credentials in files

---

# 7️⃣ Flags & Proof Collection

- [ ] Read `user.txt`
- [ ] Read `root.txt`
- [ ] Save paths to both flags in notes
- [ ] Confirm flags match HTB panel
- [ ] (Optional) Capture screenshots for documentation

---

# 8️⃣ Cleanup (Good Practice)

- [ ] Remove uploaded payloads
- [ ] Remove temporary accounts (if created)
- [ ] Remove logs **only if allowed** (HTB resets anyway)

---

# 9️⃣ Documentation

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
