#Unprotected Functionality (Canonical)

## Overview

Unprotected functionality covers admin or privileged endpoints reachable without proper authorization checks, enabling vertical privilege escalation or unauthorized actions.

## When to test

- Search for admin paths, management endpoints, `robots.txt`, or links in JS that indicate hidden functionality.

## Detection Checklist

- Crawl, inspect front-end code, check `robots.txt`, and attempt access with low-privilege sessions.

## Tools

- `gobuster`, Burp Suite, automated crawlers, and manual inspection.

## Payloads / Patterns

- Common admin paths: `/admin`, `/manage`, `/admin.php`, `/dashboard`, `/console`.

## Commands / Quick Examples

- `gobuster dir -u http://target -w /usr/share/wordlists/common.txt -x php,html` to discover hidden paths.

## Exploitation Primitives

- Direct access to privileged functionality, possible data modification or system control if checks are missing.

## Mitigations / Notes for Reporting

- Enforce server-side RBAC/authorization checks for every privileged endpoint and log access attempts.

## Detailed Notes / Lab Content

The original detailed notes are preserved below.

```markdown
#Unprotected Functionality (Vertical Privilege Escalation)

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

```

---

## Merged from archive/canonical/unprotected-functionality.md


## Unprotected Functionality (Canonical) (archived)

Archived copy of `notes/canonical/unprotected-functionality.md`. Use `notes/unprotected-functionality.md` as the merged single-file topic.

