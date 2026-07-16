# Server-Side Request Forgery Detection

Follow the output schema in `system-security.md` (JSON array of findings, category "ssrf").

Look for: outbound HTTP to a user-supplied URL/host without allowlist; include related
config/route files.
