## Resilience Lens

Review for robustness:

1. Error handling gaps: unhandled rejections, swallowed exceptions, missing error boundaries
2. Race conditions: concurrent mutations, stale closures, missing locks
3. N+1 queries: DB queries inside loops, missing select_related/prefetch_related
4. Auth/authz gaps: missing permission checks
5. Edge cases: division by zero, empty arrays, null refs, boundaries
6. Resource leaks: unclosed connections, missing cleanup
