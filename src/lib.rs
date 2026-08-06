//! Everything except the cli layer, exposed as a library **only** so the fuzz
//! targets in `fuzz/` can call the validator boundaries directly (libFuzzer
//! links against a lib, not a bin). `nyet` itself is the binary in `main.rs`;
//! nothing here is a supported public API, hence `doc(hidden)` — no semver
//! promise is made about any of it.

#![forbid(unsafe_code)]
#![doc(hidden)]

pub mod audit;
pub mod config;
pub mod engine;
pub mod guardrail;
pub mod mongo;
pub mod output;
pub mod resolver;
pub mod sample;
pub mod secret;
pub mod skill;
pub mod tunnel;
pub mod validator;
