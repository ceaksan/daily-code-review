# JWT Handling Detection

Follow the output schema in `system-security.md` (JSON array of findings, category "jwt").

Look for: `alg:none`, unverified signature, weak/hardcoded secret, missing exp check,
decode-without-verify.
