# Topic Template (Canonical)

Use this template as the single canonical file for each topic. Fill each section with concise, actionable notes, commands, and examples so the file can be used as a one-stop reference during labs.

## Title

Short one-line description of the topic.

## Overview

What the topic is and why it matters (1-3 sentences).

## When to test

Which scenarios, services or application features you should test for this topic.

## Detection Checklist

- Quick checks to perform (manual and automated).
- Indicators to look for in responses, headers, or logs.

## Tools

- Recommended tools, short rationale and typical command examples.

## Payloads / Patterns

- Concise list of go-to payloads or patterns (one per line). Put long lists in `tools/`.

## Commands / Quick Examples

Short runnable commands to reproduce tests or proof-of-concept checks.

## Exploitation Primitives

- Practical exploitation approaches and what a successful test yields (info leak, code exec, credentials, etc.).

## Mitigations / Notes for Reporting

- Short remediation items and what to include in a report.

## References

- Links to resources, CVEs, or detailed writeups.

## Detailed Notes / Lab Content

Paste longer notes, lab steps, or writeups below. When the canonical file grows too large, split lab writeups into `labs/<box>/` and keep the canonical file as a concise reference.

---

Fill this template and save as `notes/canonical/<topic>.md` for a consistent structure across topics.
