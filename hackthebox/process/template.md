# [Box Name] Writeup

> **Machine:** [Box Name]  
> **Difficulty:** [Easy/Medium/Hard/Insane]  
> **OS:** [Linux/Windows]  
> **IP Address:** [Target IP]  
> **Completed:** [Date]

---

## Overview

Brief description of the machine, key vulnerabilities, and exploitation path.

**Key Concepts:**
- Vulnerability/technique 1
- Vulnerability/technique 2
- Privilege escalation vector

---

## Enumeration

### Initial Reconnaissance

```bash
# Ping/host discovery
ping -c 1 <target-ip>

# Quick port scan
nmap -p- --open -T4 <target-ip>
```

**Results:**
- Port 22: SSH
- Port 80: HTTP
- [Add others]

### Detailed Service Scanning

```bash
nmap -sV -sC -p 22,80,... <target-ip> -oN nmap-detailed.txt
```

**Services Identified:**
- Service 1 (Port XX): Version, Details
- Service 2 (Port XX): Version, Details

### Web Application Enumeration

```bash
# Directory enumeration
ffuf -u http://<target>/FUZZ -w /path/to/wordlist

# or
dirsearch -u http://<target> -w common.txt
```

**Findings:**
- Endpoint 1: [Description]
- Endpoint 2: [Description]
- Interesting file/behavior

### Additional Enumeration

[Document any other service enumeration: SMB, databases, SSH, etc.]

---

## Vulnerability Discovery

### Vulnerability 1: [Type & Name]

**Description:**
[How the vulnerability works and where it was found]

**Testing:**
```bash
# Commands to test/confirm the vulnerability
curl -X POST ...
```

**Confirmation:**
[Evidence of vulnerability - output, screenshots, etc.]

### Vulnerability 2: [Type & Name]

[Repeat structure above]

---

## Exploitation

### Initial Access (Privilege: [User/Service])

**Vulnerability Chain:**
1. [First vulnerability exploited]
2. [Second vulnerability chained if applicable]

**Exploitation Steps:**

```bash
# Step 1: Craft payload
[command/script]

# Step 2: Upload/inject payload
[command/script]

# Step 3: Trigger execution
[command/script]
```

**Result:**
```bash
# Shell obtained as:
whoami
# output: www-data / service account
```

---

## Privilege Escalation

### Vector 1: [Type - SUID/Sudo/Cron/Kernel/etc.]

**Discovery:**
```bash
# Commands used to identify the vector
sudo -l
find / -perm -4000 2>/dev/null
```

**Findings:**
[SUID binary found, sudo misconfiguration, etc.]

### Exploitation:

```bash
# Steps to escalate
[command/script]
```

**Result:**
```bash
# Root shell obtained
whoami
# output: root
```

---

## Flags

**User Flag:**
```
[user-flag-hash]
```

**Root Flag:**
```
[root-flag-hash]
```

---

## Key Learnings & Techniques

1. **Technique 1:** [Description & where it applied]
2. **Technique 2:** [Description & where it applied]
3. **CVE/Vulnerability:** [If specific CVE, link and explanation]

---

## Tools Used

- nmap
- ffuf / dirsearch
- Burp Suite
- [Custom scripts or other tools]
- [Exploitation frameworks if used]

---

## References

- [HackTricks page for technique X]
- [Exploit-DB link for CVE-XXXX]
- [GitHub repo for tool Y]
- [GTFOBins for SUID binary]

---

## Timeline

| Step | Action | Result |
|------|--------|--------|
| 1 | Enumeration | Identified services |
| 2 | Vulnerability testing | Found SQLi/RCE/etc. |
| 3 | Initial exploitation | Gained user shell |
| 4 | PrivEsc | Escalated to root |
| 5 | Flags | Captured both flags |

---

## Notes & Challenges

[Any issues encountered, alternative approaches tried, lessons learned, or interesting behaviors]

---

## Reproduction Command

Quick one-liner or script to fully reproduce the exploitation (for quick reference):

```bash
# [Compact reproduction command or short script]
```
