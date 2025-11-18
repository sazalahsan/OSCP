#CAPTCHA Bypass (Canonical)

## Overview

CAPTCHA challenges (image, audio, math) are anti-automation controls. Weak implementations often allow bypass through predictable tokens, reuse, or missing server-side validation.

## When to test

- Login, registration, password reset, comment posting, and other endpoints protected by CAPTCHA.

## Detection Checklist

- Check whether CAPTCHA is enforced server-side, whether tokens are single-use, and whether client-side-only checks exist.

## Tools

- Tesseract (OCR), speech-to-text tools, Burp Suite, custom automation scripts, third-party solving services.

## Payloads / Patterns

- Reuse valid token across requests, remove/modify CAPTCHA parameters, test accessible/alternative endpoints.

## Commands / Quick Examples

- Use `curl` to replay requests and verify server-side validation.

## Exploitation Primitives

- Bypass by reusing tokens, exploiting client-only checks, predicting simple CAPTCHAs, or using OCR/third-party solvers.

## Mitigations / Notes for Reporting

- Enforce server-side validation, single-use tokens, rate-limiting, and monitor for repeated failures.

## Detailed Notes / Lab Content

The original detailed notes are preserved below. Keep this canonical file as a short practical checklist and move long examples to `labs/` if needed.

```markdown
#CAPTCHA Bypass Techniques

**What is CAPTCHA?**
A challenge (image, audio, math, etc.) to distinguish humans from bots, often used to block brute-force, spam, or automated attacks.

**Common Bypass Techniques:**
- **Weak implementation:** CAPTCHA only on login, not on password reset, registration, or other sensitive endpoints.
- **Reusing tokens:** CAPTCHA token/answer can be reused across multiple requests or sessions.
- **Predictable/Static challenges:** Simple math or image CAPTCHAs with a small set of possible answers.
- **Solving with OCR:** Use open-source OCR (e.g., Tesseract) or ML models to solve image CAPTCHAs.
- **Audio CAPTCHA cracking:** Use speech-to-text tools to solve audio challenges.
- **Third-party CAPTCHA-solving services:** Pay-for-use APIs or crowdsourcing (e.g., 2Captcha, Anti-Captcha).
- **Bypassing client-side validation:** CAPTCHA checked only in JavaScript, not enforced server-side.
- **Parameter tampering:** Remove or modify CAPTCHA parameters in requests; sometimes the backend does not validate.
- **Race conditions:** Send multiple requests in parallel with the same CAPTCHA token before it expires.
- **Accessibility endpoints:** Some sites offer “accessible” versions of CAPTCHAs that are easier to solve or not protected.

**Mitigation:**
- Always validate CAPTCHA server-side.
- Use per-request, single-use tokens.
- Rate-limit and monitor failed attempts.
- Use modern, adaptive CAPTCHAs (e.g., reCAPTCHA v3) and combine with other anti-automation controls.

```

---

## Merged from archive/canonical/captcha.md


## CAPTCHA (Canonical) (archived)

Archived copy of `notes/canonical/captcha.md`. Use `notes/captcha.md` as the merged single-file topic.

