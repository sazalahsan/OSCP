# Unprotected Functionality (Vertical Privilege Escalation)

**What it is:**
Sensitive functionality (e.g., admin pages, management endpoints) is reachable without proper access control. This allows vertical privilege escalation by directly visiting hidden or privileged endpoints.

**Common indicators:**
- Admin URLs accessible directly (e.g., `/admin`, `/manage`, `/admin.php`)
- Links exposed in UI, JavaScript, or `robots.txt`
- Predictable or guessable paths

**Why it matters:**
Any authenticated or unauthenticated user can perform admin actions if server-side checks are missing, leading to full compromise of application data or functionality.

**Quick tests:**
- Check `robots.txt` for disallowed or hidden paths
- Crawl and inspect HTML/JS for admin or management links
- Brute-force common admin paths (e.g., `/admin`, `/admin123`, `/manage`)
- Try accessing endpoints while logged in as a low-privilege user (or unauthenticated)

**Validation:**
- Confirm the functionality is actually accessible and works (not just an info page)
- Observe differences in response, status codes, or UI behavior compared to an admin session

**Mitigation:**
- Enforce server-side role checks on every sensitive endpoint
- Do not rely on obscurity, hidden links, or UI controls
- Use authorization middleware and audit logging for all privileged actions
