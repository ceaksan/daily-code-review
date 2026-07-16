# XML External Entity Detection

Follow the output schema in `system-security.md` (JSON array of findings, category "xxe").

Look for: XML parsers with external entity resolution enabled on untrusted XML. Watch for
`lxml`/`xml.etree`/`xml.sax` parsing request data without disabling DTD and entity
resolution. A parser configured to reject external entities is NOT a finding.
