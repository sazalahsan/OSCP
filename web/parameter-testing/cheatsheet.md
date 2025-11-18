# Parameter Testing Cheatsheet

## How to Detect Vulnerabilities in Multi-Parameter URLs

Given a URL like:
```
test.php?id=138293&reg_no=0589406&course=4&pass_year=2005&letters_code=k2nR&t0KeNdEg=qRMbth0fiT
```

### 1. Identify injectable parameters
- Numeric (`id`, `course`, `pass_year`) and string (`reg_no`, `letters_code`, `t0KeNdEg`) parameters are all candidates.
- Test each parameter individually for injection.

### 2. Manual quick tests
- For each parameter, try breaking syntax or logic:
  - `id=138293'` or `id=138293--`
  - `reg_no=0589406' OR '1'='1`
  - `course=4 OR 1=1`
- Observe for errors, content changes, or different HTTP status codes.

### 3. Automated tools
- Use Burp Suite's Repeater/Intruder or sqlmap:
  - sqlmap example:
    ```bash
    sqlmap -u "http://target/test.php?id=138293&reg_no=0589406&course=4&pass_year=2005&letters_code=k2nR&t0KeNdEg=qRMbth0fiT" --batch --level=5 --risk=3
    ```
  - Use `-p` to specify which parameter(s) to test:
    ```bash
    sqlmap ... -p id,reg_no,course,pass_year,letters_code,t0KeNdEg
    ```

### 4. Fuzzing
- Use ffuf, wfuzz, or Burp Intruder to inject payloads into each parameter and look for anomalies.

### 5. Look for:
- SQL errors, reflected input, content changes, time delays, or authentication/authorization bypasses.

### 6. Test for other vulnerabilities
- **XSS:** Inject `<script>alert(1)</script>` in string parameters.
- **LFI:** Try `../../../../etc/passwd` in parameters that look like filenames.
- **IDOR:** Change `id` or `reg_no` to another valid value and see if you can access other users' data.

### 7. Analyze parameter purpose
- Parameters like `t0KeNdEg` or `letters_code` may be anti-automation or integrity checks. Try removing or modifying them to see if the server rejects the request.

---

**Summary:**
Test each parameter individually for injection (SQLi, XSS, LFI, IDOR, etc.) using both manual payloads and automated tools. Look for errors, content changes, or unexpected behavior. Document all findings and payloads that trigger anomalies.
