# Server-Side Template Injection Detection

Follow the output schema in `system-security.md` (JSON array of findings, category "ssti").

Look for: user input rendered as a template rather than passed as data. Watch for
`Template(user_input)`, Jinja or Handlebars strings built from request data,
`render_template_string` with interpolated input. Passing user data as template
variables (not as the template body) is NOT a finding.
