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
* **Credential hunting in:**

  * registry
  * unattended.xml
  * WinRM logs
  * browser histories

**Why:**
Privilege escalation almost always derives from *trust relationships* or *misplaced permissions*.

---

# **5. Lateral Movement & Pivoting (For Domain Machines)**

### Steps seen across boxes like Forest, Active, Blackfield:

1. **Gain low-priv domain account** (anonymous LDAP, SMB loot, leaked creds)

2. **Map AD permissions** using:

   * `bloodhound-python`
   * `rpcclient`
   * `GetNPUsers`, `GetUserSPNs`

3. **Exploit trust relationships**

   * Weak Kerberos encryption → offline cracking
   * ACL misconfig → add yourself to groups
   * Password reuse across services

4. **Obtain higher-priv credentials**

   * Dumping LSASS (if possible)
   * Gaining DCSync rights
   * Abusing constrained delegation

**Reasoning:**

> AD is a web of trust. Break one weak link; climb upwards.

---

# **6. Documentation & Mindset During Attack**

Good attackers write down:

* What they tried
* What worked
* What changed

This avoids repeating failed approaches and supports faster lateral movement.

### Mental model during exploitation:

* *What am I exploiting?* (bug type)
* *Why does it work?* (misconfig, logic error, oversight)
* *What does it give me?* (information, code execution, credentials)
* *How can this access be turned into something bigger?*

---

# **7. The Universal Exploitation Loop**

The entire HTB methodology can be summarized as:

1. **Enumerate** → discover surface
2. **Fingerprint** → understand technologies
3. **Analyze** → identify vulnerabilities
4. **Exploit** → obtain foothold
5. **Escalate** → gain elevated privileges
6. **Pivot** → expand control
7. **Loot** → extract credentials / data
8. **Repeat** until Admin/System/Root

**This loop appears in every single HTB box.**

---

# **8. Tools: Not What, But Why**

### Why Enumeration Tools?

Because attackers must transform uncertainty into certainty.

### Why Exploitation Tools?

To weaponize vulnerabilities that would be tedious manually.

### Why Post-Exploitation Tools?

To observe the environment from inside and discover new paths.

### Why Scripting / One-liners?

Automation eliminates human error and speeds up repetitive tasks.

---

# **9. Strategic Patterns Across the Playlist**

Across the playlist machines, attackers consistently:

* Look for **cred leakage** in SMB, LDAP, source code, backups
* Use cracked passwords to access multiple services
* Treat Active Directory as an **attack graph**, not a single target
* Use enumeration tools to build hypotheses
* Validate hypotheses with manual testing
* Abuse **trust relationships** more often than actual software 'bugs'

---

# **10. Final Takeaways**

* HackTheBox machines reward **methodical exploration**, not guessing.
* Tools are helpers; *the attacker’s reasoning is the real weapon*.
* Always pivot from data → hypothesis → validation.
* A solid methodology outperforms deep CVE knowledge.
* Reuse patterns: the same misconfigs appear in many forms.

**This methodology mirrors the exact reasoning IppSec demonstrates in the playlist.**
