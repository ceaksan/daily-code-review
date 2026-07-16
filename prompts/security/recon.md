# Security Recon

You are mapping a repository's attack surface. Given the file inventory below and the
list of vuln classes, decide WHICH classes are applicable to THIS repo and WHICH files
each applicable class should inspect.

For cross-file classes (access-control, business-logic, ssrf, jwt), include the
dependency neighborhood: related routes, middleware, models, and relevant config files,
so a class batch carries enough context to see cross-file flaws.

Return ONLY a JSON object mapping class id -> array of repo-relative file paths:

{"sqli": ["app/db.py"], "access-control": ["app/routes.py", "app/middleware.py"]}

Omit classes that do not apply. Use only file paths that appear in the inventory.
