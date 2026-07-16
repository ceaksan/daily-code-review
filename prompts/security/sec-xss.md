# Cross-Site Scripting Detection

Follow the output schema in `system-security.md` (JSON array of findings, category "xss").

Look for: unescaped user data into HTML/templates, `dangerouslySetInnerHTML`, `|safe`,
`innerHTML`, missing auto-escaping.
