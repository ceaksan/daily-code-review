# Insecure Deserialization Detection

Follow the output schema in `system-security.md` (JSON array of findings, category "deserialization").

Look for: `pickle.loads`, `yaml.load` without `SafeLoader`, `marshal.loads`, or native
deserialization of untrusted bytes from requests, files, or network. Deserializing trusted,
internally-produced data with a safe loader is NOT a finding.
