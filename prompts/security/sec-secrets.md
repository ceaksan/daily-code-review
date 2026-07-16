# Hardcoded Secrets Detection

Follow the output schema in `system-security.md` (JSON array of findings, category "secrets").

Look for: hardcoded API keys, passwords, tokens, or private keys in source or committed
config. Report the LOCATION only (file and line), never the secret value itself. A value
read from an environment variable or an external secret store is NOT a finding.
