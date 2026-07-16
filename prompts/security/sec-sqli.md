# SQL Injection Detection

Follow the output schema in `system-security.md` (JSON array of findings, category "sqli").

Look for: string-concatenated or f-string SQL, `.format()`/`%` into queries, ORM `.raw()`
/ `.extra()` with interpolation, dynamic table/column names from user input. A parametrized
query with bound params is NOT a finding.
