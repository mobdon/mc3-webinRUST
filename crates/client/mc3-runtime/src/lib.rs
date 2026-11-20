//! mc3-runtime: hand-written runtime code moved from C to Rust, one module at a time, behind the C names
//! the rest of the build already calls (ADR 0013). Built with `-DMC3_RUST_RUNTIME=ON` (CMakeLists.txt), which drops
//! the C file a module replaces; OFF keeps the C build as it was, for A/B.
//!
//! - `crypto`: xboxrecomp/src/kernel/kernel_crypto.c (XcSHA*, XcRC4*, XcHMAC and the Xbox Live stubs).

pub mod crypto;
