# Broken Access Control (IDOR) Detection

Follow the output schema in `system-security.md` (JSON array of findings, category "access-control").

Look for: missing ownership or permission check before a resource is read or mutated.
Reason across route, middleware, and model: a handler that fetches a record by an id from
the request without confirming the current user owns or may access it is a finding. An
endpoint with an enforced ownership or role check upstream is NOT a finding.
