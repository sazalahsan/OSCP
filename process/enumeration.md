# Enumeration Checklist

Systematic reconnaissance and service enumeration for HackTheBox machines.

## Phase 1: Host Discovery

- [ ] Ping sweep (if network-based)
- [ ] Identify target IP/hostname
- [ ] Document target OS (Linux/Windows) from context or early probes

## Phase 2: Port Scanning

- [ ] Run initial quick scan: `nmap -p- --open -T4 <target>`
- [ ] Identify open ports and services
- [ ] Note common ports: 22 (SSH), 80 (HTTP), 443 (HTTPS), 445 (SMB), 3306 (MySQL), 5432 (PostgreSQL), 8080 (HTTP alt), etc.

## Phase 3: Service Version Detection

- [ ] Run service scan: `nmap -sV -p <ports> <target>`
- [ ] Identify service versions for vulnerability mapping
- [ ] Run script scan: `nmap -sC -p <ports> <target>` (if time allows)
- [ ] Combine into detailed scan: `nmap -sV -sC -p <ports> -oN nmap-detailed.txt <target>`

## Phase 4: HTTP/HTTPS Enumeration

- [ ] Check HTTP status: `curl -i http://<target>`
- [ ] Run web spider/crawler:
  - Burp Suite: Automatic crawl
  - ffuf: `ffuf -u http://<target>/FUZZ -w /path/to/wordlist`
  - dirsearch: `dirsearch -u http://<target> -w common.txt`
- [ ] Enumerate common directories: `/admin`, `/app`, `/api`, `/uploads`, `/backup`, `/config`, etc.
- [ ] Identify technologies (check response headers, HTML, JavaScript)
- [ ] Document endpoints, parameters, forms

## Phase 5: SMB Enumeration (if SMB present)

- [ ] List shares: `smbclient -L //<target>`
- [ ] Enumerate shares for null sessions: `smbclient //<target>/share -N`
- [ ] Run enum4linux or nmap smb scripts
- [ ] Check for known CVEs (EternalBlue, etc.)

## Phase 6: SSH Enumeration (if SSH present)

- [ ] Check SSH version: `ssh -v <target>`
- [ ] Identify SSH software (OpenSSH version for known CVEs)
- [ ] Note: SSH is often a secondary access vector; focus on other services first

## Phase 7: Database Enumeration (if DB present)

- [ ] Attempt connection: `mysql -h <target> -u root` or similar
- [ ] Identify database service (MySQL, PostgreSQL, MSSQL, etc.)
- [ ] Check for default credentials
- [ ] Enumerate databases/tables if accessible

## Phase 8: Credential Harvesting

- [ ] Check common locations: `/etc/passwd`, `/etc/shadow` (via LFI), config files
- [ ] Look for hardcoded credentials in code/config files
- [ ] Check for weak default credentials on services
- [ ] Use tools: `hashcat`, `john` for offline cracking if hashes found

## Phase 9: Vulnerability Identification

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

## Phase 10: Documentation

- [ ] Document all open ports, services, versions
- [ ] Record interesting findings (default credentials, interesting endpoints, potential vulnerabilities)
- [ ] Capture screenshots/outputs
- [ ] Prepare for exploitation phase

## Tools Reference

- **nmap** – Port scanning & service detection
- **ffuf** – Web directory/parameter fuzzing
- **burp suite** – Web proxy & analysis
- **enum4linux** – SMB enumeration
- **curl/wget** – Manual HTTP testing
- **dirsearch** – Directory enumeration
- **nikto** – Web server scanning (optional)

## Notes

- Start broad (all ports), then narrow down (specific services).
- Document everything; early findings may connect to later vectors.
- Prioritize services with known public exploits.
- Never assume a service is uninteresting until tested.
