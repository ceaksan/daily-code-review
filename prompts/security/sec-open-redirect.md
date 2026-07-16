# Open Redirect Detection

Follow the output schema in `system-security.md` (JSON array of findings, category "open-redirect").

Look for: a redirect target taken from user input without an allowlist. Watch for
`redirect(request.args["next"])`, `Location` headers built from query or form data, and
`window.location` set from untrusted input. A redirect restricted to a known-safe set of
paths or hosts is NOT a finding.
