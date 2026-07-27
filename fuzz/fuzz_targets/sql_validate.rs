//! Panic-freedom for layer 1's SQL half: `validator::validate` must return a
//! verdict for ANY string, never unwind.
//!
//! The oracle is indirect on purpose. `validate` wraps itself in `catch_unwind`
//! (a panic is a bug, but it must not escape as an abort — Д3), so libFuzzer
//! would never see the panic it catches: it comes back as an ordinary refusal
//! with `reason = INTERNAL_ERROR`. So THAT is what this target treats as the
//! crash. Panics from anywhere outside the guarded region — the refusal
//! builders, `Display` impls — still reach libFuzzer the normal way.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nyetdb::validator::{self, DenyReason, Policy, Verdict};
use std::sync::LazyLock;

/// Every dialect on every input, rather than picking one with a byte of the
/// input: the dialects share a parser and differ only in tables of names, so a
/// single mutation is worth three verdicts — and it keeps the seed corpus
/// literal SQL, byte for byte the text a user would type.
static POLICIES: LazyLock<[Policy; 3]> = LazyLock::new(|| {
    [
        Policy::sqlite(&[], &[]),
        Policy::postgres(&[], &[]),
        Policy::mysql(&[], &[]),
    ]
});

fuzz_target!(|sql: &str| {
    for policy in POLICIES.iter() {
        if let Verdict::Deny {
            reason: DenyReason::InternalError,
            message,
            ..
        } = validator::validate(sql, policy)
        {
            panic!("validator panicked on {sql:?}: {message}");
        }
    }
});
