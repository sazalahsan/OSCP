#Parameter Testing (Canonical)

## Overview

Parameter testing is the practice of testing each URL/form parameter for common vulnerabilities (SQLi, XSS, LFI, IDOR, command injection) — especially when multiple parameters are present.

## When to test

- Any multi-parameter endpoint (search, filter, update) and any parameter that influences logic or accesses resources.

## Detection Checklist

- Test each parameter individually with relevant payloads (SQLi payloads for numeric/string params, XSS for reflected strings, LFI payloads for file-like params).

## Tools

- Burp Suite (Intruder/Repeater), `sqlmap` (with `-p` to specify parameters), `ffuf`, custom scripts.

## Payloads / Patterns

- SQLi: `' OR '1'='1`  
- XSS: `<script>alert(1)</script>`  
- LFI: `../../../../etc/passwd`

## Commands / Quick Examples

- `sqlmap -u "http://target/test.php?param=1&other=2" -p param --batch`

## Exploitation Primitives

- Identify which parameter(s) are vulnerable and whether chaining parameters produces additional impact (e.g., IDOR combined with auth tokens).

## Mitigations / Notes for Reporting

- Validate and sanitize all parameters, use parameterized queries, and enforce access controls server-side.

## Detailed Notes / Lab Content

The longer parameter-testing cheatsheet (original) is preserved below for reference and contains manual quick tests, fuzzing notes, and automation examples.

````markdown
#Parameter Testing Cheatsheet

## How to Detect Vulnerabilities in Multi-Parameter URLs

Given a URL like:
```
test.php?id=138293&reg_no=0589406&course=4&pass_year=2005&letters_code=k2nR&t0KeNdEg=qRMbth0fiT

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
    sqlmap ... -p id,reg_no,course,pass_year,letters_code,t0KeNdEg

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

````

## Parameter Testing Cheatsheet


## Merged from archive/canonical/parameter-testing.md


## Parameter Testing (Canonical) (archived)

Archived copy of `notes/canonical/parameter-testing.md`. Use `notes/parameter-testing.md` as the merged single-file topic.

