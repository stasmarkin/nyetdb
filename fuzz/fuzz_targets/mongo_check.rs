//! Panic-freedom for layer 1's MongoDB half: `mongo::check` must return a
//! request or a refusal for ANY string, never unwind.
//!
//! Same oracle as `sql_validate` — `check` shares the SQL validator's
//! `catch_unwind`, so a caught panic surfaces as `reason = INTERNAL_ERROR` and
//! that is what counts as the crash here.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nyetdb::mongo;

fuzz_target!(|text: &str| {
    if let Err(r) = mongo::check(text) {
        assert_ne!(
            r.reason,
            mongo::INTERNAL_ERROR,
            "mongo::check panicked on {text:?}: {}",
            r.message
        );
    }
});
