//! Panic-freedom for the `[pii]` half of MongoDB layer 1, which `mongo_check`
//! never reaches (an empty policy makes `PiiCtx::of` return `None` and every
//! PII path dead code under fuzzing — found in review). Two probes per input:
//!
//! 1. `check_with_pii` under a non-trivial policy, in BOTH modes — exercises
//!    the mention collector (`check_ref`'s `$$var.path` stripping included),
//!    the mask projection relaxation, `check_stage`'s name positions,
//!    `collect_collections` and the `PII_UNPROVABLE_KEYS` gate.
//! 2. When the input happens to be JSON, `scan_reply` over it as a result
//!    cell — exercises net B's recursive scan (redaction and refusal alike).
//!
//! Same oracle as the siblings: a caught panic surfaces as
//! `reason = INTERNAL_ERROR`, and that is what counts as the crash.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nyetdb::mongo;
use nyetdb::validator::{PiiMode, PiiRules};

fn policy(mode: PiiMode) -> PiiRules {
    // Short names maximize accidental hits in fuzzer-mangled input; `users`
    // matches the collection most seeds mention.
    PiiRules::parse(
        &["users.email".to_string(), "users.a".to_string()],
        mode,
    )
    .expect("static rules parse")
}

fuzz_target!(|text: &str| {
    for mode in [PiiMode::Deny, PiiMode::Mask] {
        if let Err(r) = mongo::check_with_pii(text, &policy(mode)) {
            assert_ne!(
                r.reason,
                mongo::INTERNAL_ERROR,
                "check_with_pii panicked on {text:?}: {}",
                r.message
            );
        }
        if let Ok(cell) = serde_json::from_str::<serde_json::Value>(text) {
            let columns = vec!["a".to_string(), "x".to_string()];
            let mut rows = vec![vec![cell.clone(), cell]];
            if let Err(r) =
                mongo::scan_reply("db.users.find({})", &policy(mode), &columns, &mut rows)
            {
                assert_ne!(
                    r.reason,
                    mongo::INTERNAL_ERROR,
                    "scan_reply panicked on {text:?}: {}",
                    r.message
                );
            }
        }
    }
});
