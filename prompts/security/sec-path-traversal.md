# Path Traversal Detection

Follow the output schema in `system-security.md` (JSON array of findings, category "path-traversal").

Look for: user input joined into filesystem paths without normalization or containment.
Watch for `os.path.join`/`Path` built from request data, missing `..` rejection, missing
resolve-and-contain checks. A path validated against an allowed base directory is NOT a finding.
