## Architecture Lens

Review against the project's architecture document:

1. Layer violations: business logic in views/controllers? Components hitting DB directly?
2. Pattern compliance: does code follow patterns in the architecture doc?
3. Coupling: would changing one file break many others?
4. Dependency direction: UI -> Service -> Repository -> DB, not reversed?
5. Module boundaries: is code in the right place per architecture?
