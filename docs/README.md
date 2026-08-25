Docs for SysCall-DAG

Files created
- flow.md — step-by-step runtime & pipeline flow (trace → graph → fingerprint → decision).
- architecture.md — module responsibilities, data models, and algorithm pointers.
- features.md — user-facing feature list, quickstart commands, and where to look for extension points.

Suggested next steps for maintainers
1. Review docs and add module-level examples (small code snippets) where helpful.
2. Add architecture diagrams (mermaid) for onboarding if desired.
3. Run `cargo test` to validate unchanged behavior after doc additions.

Repository layout reminder
- src/ — implementation (see architecture.md)
- configs/ — default configuration
- tests/ — golden traces and pipeline tests
- examples/ — demo workload

If more documentation is needed (API references, dev setup, CI), specify and a follow-up commit will be added.
