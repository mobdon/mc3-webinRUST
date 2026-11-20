# 0013: One Rust workspace, split into client, server and shared

Date: 2026-11-20. Status: accepted (owner).

## Context

The hand-written code is moving to Rust: today only the server (`web/server`) is Rust, the browser runtime
(`xboxrecomp/src`, `src/`) is C. A later step splits the repository into a client repository and a server
repository. The C the lifter generates from a player's disc (~2.9 M lines) stays C: it is machine output, never edited
and never committed.

## Decision

- One Cargo workspace at the repo root (`Cargo.toml`, one `Cargo.lock`, one `target/`).
- Crates in three groups:
  - `crates/shared/*`: what client and server both speak (wire formats; `mc3-proto`). No I/O, no platform code.
  - `crates/server/*`: `mc3-server` (was `web/server`), `ws`, `lan`, `roam`.
  - `crates/client/*`: the runtime and game glue as they are ported from C (later phases).
- A server crate never depends on a client crate, and the reverse. Both may depend on shared crates only.
- C modules are replaced one at a time behind their existing C names (`extern "C"`), so the generated code, the
  CMake/Emscripten build and the page do not change, and each swap can be A/B tested.
- At the split, `crates/server` (+ `web/lan-worker`, `web/races-worker`) and `crates/client` (+ `web/`, the lifter)
  become their own repositories with history (`git filter-repo`); `crates/shared` becomes a dependency of both.

## Consequences

- Build the server from the repo root: `cargo build --release -p mc3-server`; its paths are relative to the root.
- The roam wire format lives in `mc3-proto::roam`; `mc3-roam` re-exports it, so its API is unchanged.
- Licences do not change: the moved crates keep MIT (after nfsu2-web), new client crates take the repo's AGPL-3.0.
