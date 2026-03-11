## Duplication Lens

Look for semantic duplication:

1. Copy-paste code across files (even with different variable names)
2. Same validation rules in multiple places
3. Parallel structures that should share a base
4. Shotgun surgery candidates: changing one concept requires N file edits
5. 3+ similar blocks that need a shared utility

Do NOT flag: intentional duplication for clarity, test fixtures, similar but semantically different code.
