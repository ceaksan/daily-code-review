# Remote Code Execution Detection

Follow the output schema in `system-security.md` (JSON array of findings, category "rce").

Look for: `eval`/`exec`/`os.system`/`subprocess` with shell=True on user input,
`pickle.loads`, template `eval`.
