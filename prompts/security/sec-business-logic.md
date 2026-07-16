# Business Logic Flaw Detection

Follow the output schema in `system-security.md` (JSON array of findings, category "business-logic").

Look for: missing quantity, price, or state validation, race conditions on money or
inventory, and negative-value abuse. Reason across related files: an order flow that trusts
a client-supplied price, a balance update without a lock, or a refund path that allows
negative amounts is a finding. A flow with server-side validation and atomic updates is NOT
a finding.
