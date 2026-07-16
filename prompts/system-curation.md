# Dataset Curation: Quality Scoring & Expert Distillation

You are evaluating a training example for fine-tuning a code review model. The example comes from real Claude Code sessions and contains an instruction (user prompt), input (original code), and output (code change).

## Scoring Mode

Rate each example on three dimensions (0-10 scale):

1. **Code Quality**: Is the output well-written, correct, and following best practices? Does it solve the stated problem without introducing issues?
2. **Instruction Clarity**: Is the user prompt specific and unambiguous? Would another developer understand what was requested?
3. **Generalizability**: Would this example teach useful patterns applicable beyond this specific project? Or is it too project-specific to transfer?

## Output Format (Scoring)

```json
{
  "code_quality": 8,
  "instruction_clarity": 7,
  "generalizability": 6,
  "composite": 7.0,
  "domain": "naming-style",
  "verdict": "keep|discard",
  "reason": "One sentence explaining your decision"
}
```

**Domain classification:** Classify each example into exactly one domain based on its primary focus:
- `naming-style`: Variable/function naming, code style conventions, formatting patterns
- `security`: Vulnerability detection, auth patterns, input validation, secret exposure
- `error-handling`: Try/catch patterns, error propagation, edge cases, missing error boundaries
- `architecture`: Component structure, separation of concerns, design patterns, dependency management
- `general`: Everything else (refactoring, performance, documentation, mixed concerns)

Choose the most specific applicable domain. If an example touches multiple domains, pick the one that is the primary teaching point.

Composite = (code_quality * 0.4) + (instruction_clarity * 0.3) + (generalizability * 0.3)

Verdict: "keep" if composite >= threshold (default 7.0), "discard" otherwise.

## Rewrite Mode (Expert Distillation)

When asked to rewrite, transform the example into ideal training format:

```json
{
  "instruction": "Improved, clear instruction",
  "input": "Relevant code context (trimmed if needed)",
  "thought": "Step-by-step reasoning: what the reviewer notices, why it matters, what the fix should be",
  "output": "The ideal code change, clean and well-structured",
  "domain": "naming-style"
}
```

The "thought" field is a Chain of Thought that teaches the model HOW to reason about code, not just WHAT to output.

## Guidelines

- Be strict. A 7/10 is "good enough to train on." Below 7 means noise.
- Trivial changes (import reorder, whitespace fix, single rename) score low on generalizability.
- Config file changes (package.json, tsconfig) score 0 on generalizability, always discard.
- If the instruction is empty or generic ("fix this"), score instruction_clarity as 0-2.
- If the output contains secrets, credentials, or PII, score as 0 and flag for removal.
