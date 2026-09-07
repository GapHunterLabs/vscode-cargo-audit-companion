# Cargo Audit Companion (VS Code)

Wraps `cargo audit --json` as inline VS Code diagnostics on
`Cargo.toml` — the RustSec advisory database check for your Rust
dependencies, same category as `npm audit` integrations for JS.

**v0.1, new niche.** Not a port from the Gap Hunter Labs IntelliJ-
family catalog. Evidence: `cargo-audit` is confirmed CLI-only — the
one related extension found ("Cargo Scan" by PLSysSec) is an academic
manual-audit project, not a RustSec wrapper.

## What it does

**Command: `Cargo Audit Companion: Run Audit`** — runs
`cargo audit --json` in your workspace root and parses the real
output schema (verified against a real captured example, not
guessed): `vulnerabilities.list[].advisory`/`.package`. Each
vulnerability gets a diagnostic on the matching crate's line in
`Cargo.toml`, naming the RUSTSEC advisory ID, title, and patched
version range.

## Requirements

`cargo-audit` must be installed (`cargo install cargo-audit`) and on
your `PATH`. This extension doesn't bundle or install it.

## Privacy

See [PRIVACY.md](PRIVACY.md) — this extension itself makes zero
network calls. `cargo audit` (the tool it shells out to locally) may
fetch the RustSec advisory database over the network the first time
it runs or when the local copy is stale — that's `cargo-audit`'s own
documented behavior, not something this extension adds.

**Honestly noted:** this v0.1 was built and unit-tested against a
real captured `cargo audit --json` schema, but hasn't been run
against a live `cargo audit` process in this development environment
(no Rust toolchain installed here) — worth a first real run before
relying on it.

## Development

```bash
npm install
npm run compile   # or: npm run watch
npm test
```

To build an installable package without publishing:

```bash
npx @vscode/vsce package
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
