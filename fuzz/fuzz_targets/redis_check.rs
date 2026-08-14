//! Panic-freedom for layer 1's Redis half: `redis::parse` + `redis::check` must
//! return a verdict for ANY string, never unwind.
//!
//! Unlike the SQL target, there is no `catch_unwind` inside to work around —
//! `src/redis.rs` is a hand-written tokenizer over `char`s and a handful of set
//! lookups, so a panic reaches libFuzzer directly. What is being hunted is the
//! tokenizer: quote state, `\`-escapes at the end of input, and the container
//! split (`args.remove(0)` on a command whose subcommand is the last token).
//!
//! Every flag combination is tried on every input rather than one chosen from
//! the bytes: the classification is a handful of branches and running all of
//! them keeps the seed corpus literal Redis commands, byte for byte what a user
//! would type.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nyetdb::redis::{self, Flags};
use std::collections::BTreeSet;

fuzz_target!(|command: &str| {
    let Ok(parsed) = redis::parse(command) else {
        return;
    };
    // The lookup name and the wire vector are what the engine builds from the
    // parse; exercising them here is what makes a panic in either a fuzz
    // finding rather than a runtime surprise.
    let _ = parsed.lookup_name();
    let _ = parsed.wire();
    let denied = redis::denylist(&[], &[]);
    let allowed: BTreeSet<String> = redis::allowlist(&[parsed.name.clone()]);
    let empty = BTreeSet::new();
    for bits in 0..32u8 {
        let flags = Flags {
            readonly: bits & 1 != 0,
            write: bits & 2 != 0,
            admin: bits & 4 != 0,
            blocking: bits & 8 != 0,
            dangerous: bits & 16 != 0,
        };
        let _ = redis::check(&parsed, Some(flags), &denied, &empty);
        let _ = redis::check(&parsed, Some(flags), &denied, &allowed);
    }
    let _ = redis::check(&parsed, None, &denied, &empty);
});
