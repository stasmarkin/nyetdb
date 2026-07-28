//! MongoDB end-to-end: drive the real binary against a throwaway `mongo:8`
//! container (testcontainers + Docker/colima). Requires a reachable Docker
//! daemon; this test fails (not skips) without one, like the other engines'.
//! Pins exit codes and envelope structure (Д7) plus the two claims that only a
//! live server can settle: that the row limit and the timeout really bite, and
//! that layer 1 refuses a write BEFORE the server ever sees it.
//!
//! Everything runs in ONE container: starting one costs seconds, and the cases
//! are independent of each other.

use mongodb::bson::{doc, Document};
use std::path::Path;
use std::process::{Command, Output};
use testcontainers_modules::mongo::Mongo;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt};

/// Digest-pinned like the SSH stand's image: a future `mongo:8` push must not
/// silently change the server this test reasons about. Refresh consciously
/// (`docker pull mongo:8 && docker inspect --format '{{index .RepoDigests 0}}'
/// mongo:8`); `8@sha256:...` is a valid ref and docker resolves by digest.
const MONGO_TAG: &str = "8@sha256:e0ce8c35124d4a9f9785532d1f268f39e9728ffa1cb38f46fa482436424c4bd3";

/// A distinctive password so a leak into stdout/stderr is unmistakable.
const PW: &str = "s3cr3t_mongo_xyz";
const PW_ENV: &str = "NYET_MONGO_TEST_PW";

fn multi_thread_rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// The official image restarts mongod once while it applies
/// MONGO_INITDB_ROOT_*, so "the log said it is listening" is not enough — poll
/// a real ping instead of racing the restart.
async fn client_when_ready(url: &str) -> mongodb::Client {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let client = mongodb::Client::with_uri_str(url).await;
        if let Ok(client) = client {
            if client
                .database("admin")
                .run_command(doc! { "ping": 1 })
                .await
                .is_ok()
            {
                return client;
            }
        }
        assert!(std::time::Instant::now() < deadline, "mongo never came up");
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
}

/// Start `mongo:8` WITH authentication (the root env vars turn it on), seed the
/// data, and create the read-only account nyet connects as — so layer 3 is a
/// real thing in this test, not an assumption.
async fn start_and_seed() -> (ContainerAsync<Mongo>, u16) {
    let container = Mongo::default()
        .with_tag(MONGO_TAG)
        .with_env_var("MONGO_INITDB_ROOT_USERNAME", "root")
        .with_env_var("MONGO_INITDB_ROOT_PASSWORD", PW)
        .start()
        .await
        .expect("start mongo:8 (is docker/colima running?)");
    let port = container.get_host_port_ipv4(27017).await.unwrap();

    let root = client_when_ready(&format!(
        "mongodb://root:{PW}@127.0.0.1:{port}/admin?directConnection=true"
    ))
    .await;
    let db = root.database("test");

    // Five small documents with DELIBERATELY different shapes: one carries a
    // nested document and an array, one is missing a field the others have —
    // which is what makes "the columns are the union of the top-level keys" a
    // real claim rather than a tautology.
    db.collection::<Document>("small")
        .insert_many(vec![
            doc! { "_id": 1, "name": "ann", "tags": ["a", "b"], "profile": { "city": "Berlin" } },
            doc! { "_id": 2, "name": "bob", "tags": [] },
            doc! { "_id": 3, "name": "cyd", "extra": 42 },
            doc! { "_id": 4, "name": "dee" },
            doc! { "_id": 5, "name": "eve" },
        ])
        .await
        .unwrap();

    // Thirty documents of ~1 MB: MongoDB cuts a reply at 16 MiB, so a read of
    // all of them comes back SHORT of the row limit — the case that used to be
    // reported as a complete answer.
    let fat: Vec<Document> = (0..30)
        .map(|n| doc! { "_id": n, "blob": "x".repeat(1_000_000) })
        .collect();
    db.collection::<Document>("fat")
        .insert_many(fat)
        .await
        .unwrap();

    // Enough documents that an un-indexed self-join cannot finish inside a
    // one-second timeout.
    let many: Vec<Document> = (0..20_000).map(|n| doc! { "n": n, "m": n }).collect();
    db.collection::<Document>("many")
        .insert_many(many)
        .await
        .unwrap();

    // Array fields, to pin nyet's distinct against the real `distinct`
    // command: the pipeline nyet runs instead must agree with it for every
    // shape nyet still accepts.
    db.collection::<Document>("arr")
        .insert_many(vec![
            doc! { "_id": 1, "k": ["p", "q"], "items": [ { "sku": 1 }, { "sku": 2 } ] },
            doc! { "_id": 2, "k": "p", "items": [ { "sku": 2 } ] },
            doc! { "_id": 3 },
        ])
        .await
        .unwrap();

    // A collection with a DECLARED $jsonSchema validator: the one thing in
    // MongoDB that is a real schema, and the only source `nyet schema` is
    // allowed to present as one.
    db.run_command(doc! {
        "create": "validated",
        "validator": { "$jsonSchema": {
            "bsonType": "object",
            "required": ["email"],
            "properties": {
                "email": { "bsonType": "string" },
                "age": { "bsonType": ["int", "null"] },
            },
        }},
    })
    .await
    .unwrap();
    db.collection::<Document>("validated")
        .insert_many(vec![
            doc! { "email": "a@b.c", "age": 30, "note": "only in some documents" },
            doc! { "email": "d@e.f" },
        ])
        .await
        .unwrap();
    db.run_command(doc! {
        "createIndexes": "validated",
        "indexes": [ { "key": { "email": 1 }, "name": "email_1", "unique": true } ],
    })
    .await
    .unwrap();
    // A view plus a role scoped to it: the README's own recipe for exposing a
    // curated slice, and the setup where `listCollections` is Unauthorized.
    db.run_command(doc! { "create": "small_view", "viewOn": "small", "pipeline": [] })
        .await
        .unwrap();
    db.run_command(doc! {
        "createRole": "viewonly",
        "privileges": [ { "resource": { "db": "test", "collection": "small_view" },
                          "actions": ["find"] } ],
        "roles": [],
    })
    .await
    .unwrap();

    // Layer 3: the account nyet uses may only READ.
    for (user, roles) in [
        ("app", vec![doc! { "role": "read", "db": "test" }]),
        // Read here, WRITE somewhere else in the same cluster: the role doctor
        // must not call read-only (measured: `$out: {db: "scratch"}` copies a
        // collection out of `test` with exactly these grants).
        (
            "app_rw",
            vec![
                doc! { "role": "read", "db": "test" },
                doc! { "role": "readWrite", "db": "scratch" },
            ],
        ),
        ("app_view", vec![doc! { "role": "viewonly", "db": "test" }]),
    ] {
        root.database("test")
            .run_command(doc! { "createUser": user, "pwd": PW, "roles": roles })
            .await
            .unwrap();
    }
    (container, port)
}

/// A config naming a specific account, for the doctor/schema cases that are
/// about the ROLE rather than about the query.
fn write_config_as(dir: &Path, port: u16, user: &str) -> std::path::PathBuf {
    let path = dir.join(format!("config_{user}.toml"));
    std::fs::write(
        &path,
        format!(
            "[connections.mg]\nengine = \"mongodb\"\n\
             url = \"mongodb://{user}@127.0.0.1:{port}/test\"\n\
             password_env = \"{PW_ENV}\"\nallowed_dirs = [\"{}\"]\n",
            dir.display()
        ),
    )
    .unwrap();
    path
}

/// The status of one doctor check, by name.
fn check_status(v: &serde_json::Value, name: &str) -> String {
    v["checks"]
        .as_array()
        .unwrap_or_else(|| panic!("no checks in {v}"))
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("no {name} check in {v}"))["status"]
        .as_str()
        .unwrap()
        .to_string()
}

fn write_config(dir: &Path, port: u16, extra: &str) -> std::path::PathBuf {
    let path = dir.join(format!("config{}.toml", extra.len()));
    std::fs::write(
        &path,
        format!(
            "[connections.mg]\nengine = \"mongodb\"\n\
             url = \"mongodb://app@127.0.0.1:{port}/test\"\n\
             password_env = \"{PW_ENV}\"\nallowed_dirs = [\"{}\"]\n{extra}",
            dir.display()
        ),
    )
    .unwrap();
    path
}

fn run(home: &Path, cfg: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nyet"))
        .env_clear()
        .env("HOME", home)
        .env(PW_ENV, PW)
        .current_dir(home)
        .args(args)
        .arg("--config")
        .arg(cfg)
        .output()
        .unwrap()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}
fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn envelope(out: &Output) -> serde_json::Value {
    serde_json::from_str(stdout(out).trim()).unwrap()
}

fn assert_no_password_leak(out: &Output) {
    assert!(!stdout(out).contains(PW), "password leaked to stdout");
    assert!(!stderr(out).contains(PW), "password leaked to stderr");
}

#[test]
fn mongo_query_end_to_end() {
    multi_thread_rt().block_on(async {
        let (container, port) = start_and_seed().await;
        let tmp = tempfile::tempdir().unwrap();
        let cfg = write_config(tmp.path(), port, "");
        // The same read-only account nyet uses, for the assertions that must
        // go AROUND nyet (comparing against the server's own answer, and
        // proving layer 3 refuses what layer 1 already did).
        let app_client = client_when_ready(&format!(
            "mongodb://app:{PW}@127.0.0.1:{port}/test?directConnection=true"
        ))
        .await;

        // 1) A plain read: the envelope, the union of the documents' top-level
        //    keys as columns, and nested values kept as nested JSON.
        let out = run(
            tmp.path(),
            &cfg,
            &["query", "mg", "db.small.find({}).sort({_id: 1})"],
        );
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        assert_no_password_leak(&out);
        let v = envelope(&out);
        assert_eq!(v["ok"], true);
        assert_eq!(v["meta"]["row_count"], 5);
        assert_eq!(v["meta"]["truncated"], false);
        assert_eq!(v["rows"][0]["name"], "ann");
        assert_eq!(v["rows"][0]["profile"]["city"], "Berlin");
        assert_eq!(v["rows"][0]["tags"][1], "b");
        // A field only some documents carry is null in the others, never a
        // shifted value.
        assert_eq!(v["rows"][0]["extra"], serde_json::Value::Null);
        assert_eq!(v["rows"][2]["extra"], 42);
        // The connection is plaintext, and nyet says so rather than implying
        // an encrypted transport it does not have (UX-7).
        assert!(
            v["warnings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|w| w["code"] == "INSECURE_TRANSPORT"),
            "{v}"
        );

        // 2) The other read shapes.
        let out = run(
            tmp.path(),
            &cfg,
            &["query", "mg", "db.small.countDocuments()"],
        );
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        assert_eq!(envelope(&out)["rows"][0]["count"], 5);

        let out = run(
            tmp.path(),
            &cfg,
            &["query", "mg", "db.small.distinct(\"name\")"],
        );
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        assert_eq!(envelope(&out)["meta"]["row_count"], 5);

        let out = run(
            tmp.path(),
            &cfg,
            &[
                "query",
                "mg",
                "db.small.aggregate([{$match: {name: {$in: [\"ann\", \"bob\"]}}}, \
                 {$group: {_id: null, n: {$sum: 1}}}])",
            ],
        );
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        assert_eq!(envelope(&out)["rows"][0]["n"], 2);

        // A document result renders in the human formats too (nested values as
        // compact JSON, exactly like a PostgreSQL jsonb column).
        let out = run(
            tmp.path(),
            &cfg,
            &[
                "query",
                "mg",
                "db.small.find({_id: 1})",
                "--format",
                "table",
            ],
        );
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        assert!(stdout(&out).contains("Berlin"), "{}", stdout(&out));

        // 3) The row limit really truncates, and says so.
        let small = write_config(tmp.path(), port, "row_limit = 2\n");
        let out = run(tmp.path(), &small, &["query", "mg", "db.small.find({})"]);
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        let v = envelope(&out);
        assert_eq!(v["meta"]["row_count"], 2);
        assert_eq!(v["meta"]["truncated"], true);
        assert_eq!(v["warnings"][0]["code"], "TRUNCATED");
        // The agent's own .limit() may lower it, never raise it.
        let out = run(
            tmp.path(),
            &small,
            &["query", "mg", "db.small.find({}).limit(5)"],
        );
        assert_eq!(envelope(&out)["meta"]["row_count"], 2);
        let out = run(
            tmp.path(),
            &small,
            &["query", "mg", "db.small.find({}).limit(1)"],
        );
        let v = envelope(&out);
        assert_eq!(v["meta"]["row_count"], 1);
        assert_eq!(v["meta"]["truncated"], false);

        // 3b) The SERVER's own 16 MiB reply cap cuts the batch before the row
        //     limit is reached. The answer is short AND incomplete, and it must
        //     say so — this read as `truncated: false` before, i.e. a partial
        //     answer presented as the whole truth.
        for query in ["db.fat.find({})", "db.fat.aggregate([{$match: {}}])"] {
            let out = run(tmp.path(), &cfg, &["query", "mg", query, "--limit", "1000"]);
            assert_eq!(out.status.code(), Some(0), "{query}: {}", stderr(&out));
            let v = envelope(&out);
            let rows = v["meta"]["row_count"].as_u64().unwrap();
            assert!(rows < 30, "{query}: the server should have cut the batch");
            assert_eq!(v["meta"]["truncated"], true, "{query}: {v}");
            let warning = v["warnings"]
                .as_array()
                .unwrap()
                .iter()
                .find(|w| w["code"] == "TRUNCATED")
                .unwrap_or_else(|| panic!("{query}: no TRUNCATED warning in {v}"))
                .clone();
            // Д10: telling the agent to raise --limit here would be wrong — the
            // limit was never reached.
            let text = warning["message"].as_str().unwrap();
            assert!(text.contains("16 MiB"), "{text}");
        }

        // 4) The timeout is real: an un-indexed self-join over 20k documents,
        //    with a $group so the trailing $limit cannot be pushed under it.
        let out = run(
            tmp.path(),
            &cfg,
            &[
                "query",
                "mg",
                "db.many.aggregate([{$lookup: {from: \"many\", as: \"x\", let: {v: \"$n\"}, \
                 pipeline: [{$match: {$expr: {$eq: [\"$m\", \"$$v\"]}}}]}}, \
                 {$group: {_id: null, n: {$sum: {$size: \"$x\"}}}}])",
                "--timeout",
                "1",
            ],
        );
        assert_eq!(out.status.code(), Some(8), "{}", stdout(&out));
        assert_eq!(envelope(&out)["error"]["code"], "TIMEOUT");

        // 4b) `distinct` obeys the row limit like every other read: it runs as a
        //     bounded aggregation, so the values are cut SERVER-side rather
        //     than pulled over the network and trimmed in the CLI.
        let out = run(
            tmp.path(),
            &small,
            &["query", "mg", "db.small.distinct(\"name\")"],
        );
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        let v = envelope(&out);
        assert_eq!(v["meta"]["row_count"], 2);
        assert_eq!(v["meta"]["truncated"], true);
        assert_eq!(v["rows"][0]["value"], "ann");

        // 4b-2) nyet's distinct must AGREE with the `distinct` command for the
        //       shapes it accepts — including a direct array field, whose
        //       elements the command returns individually.
        let out = run(tmp.path(), &cfg, &["query", "mg", "db.arr.distinct(\"k\")"]);
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        let ours: Vec<String> = envelope(&out)["rows"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|r| r["value"].as_str().map(str::to_string))
            .collect();
        let theirs = app_client
            .database("test")
            .collection::<Document>("arr")
            .distinct("k", doc! {})
            .await
            .unwrap();
        let mut theirs: Vec<String> = theirs
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
        theirs.sort();
        assert_eq!(ours, theirs, "distinct must match the command's own answer");

        //       A dotted path into a sub-document is REFUSED rather than
        //       answered wrongly: $unwind cannot descend through `items` on the
        //       way to `sku`, so the pipeline would report whole arrays as
        //       distinct values (measured: [null, [1,2], [2]] instead of [1,2]).
        let out = run(
            tmp.path(),
            &cfg,
            &["query", "mg", "db.arr.distinct(\"items.sku\")"],
        );
        assert_eq!(out.status.code(), Some(5), "{}", stdout(&out));
        assert_eq!(envelope(&out)["error"]["reason"], "DENIED_COMMAND");

        // 4c) The internal catalogs are unreachable through a STAGE too — this
        //     is the form that returned system.js under this very `read` role
        //     before the fix (a collection name is a string VALUE, so the
        //     $-key allowlist never saw it).
        for query in [
            "db.small.aggregate([{$lookup: {from: \"system.js\", pipeline: [], as: \"j\"}}])",
            "db.small.aggregate([{$unionWith: \"system.profile\"}])",
            "db.small.aggregate([{$unionWith: {coll: \"system.js\", pipeline: []}}])",
        ] {
            let out = run(tmp.path(), &cfg, &["query", "mg", query]);
            assert_eq!(out.status.code(), Some(5), "{query}: {}", stdout(&out));
            assert_eq!(
                envelope(&out)["error"]["reason"],
                "DENIED_COMMAND",
                "{query}"
            );
        }

        // 5) A write is refused by LAYER 1 — before the server is asked, and
        //    therefore without a database error to explain it away.
        for query in [
            "db.small.aggregate([{$match: {}}, {$out: \"copy\"}])",
            "db.small.aggregate([{$merge: {into: \"copy\"}}])",
            "db.small.insertOne({_id: 99})",
            "db.small.find({$where: \"true\"})",
        ] {
            let out = run(tmp.path(), &cfg, &["query", "mg", query]);
            assert_eq!(out.status.code(), Some(5), "{query}: {}", stdout(&out));
            let v = envelope(&out);
            assert_eq!(v["error"]["code"], "NYET", "{query}");
            assert!(v["error"]["hint"].is_string(), "{query}");
        }
        // Nothing was created: the refusal happened above the driver.
        let root = client_when_ready(&format!(
            "mongodb://root:{PW}@127.0.0.1:{port}/admin?directConnection=true"
        ))
        .await;
        let names = root.database("test").list_collection_names().await.unwrap();
        assert!(!names.contains(&"copy".to_string()), "{names:?}");
        assert_eq!(
            root.database("test")
                .collection::<Document>("small")
                .count_documents(doc! {})
                .await
                .unwrap(),
            5,
            "the seeded data must be untouched"
        );

        // 6) Layer 3 is really underneath: the SAME `$out`, sent by the SAME
        //    account but around nyet, is refused by the SERVER. That is what
        //    makes "layer 1 refuses first" a defence in depth rather than the
        //    only thing standing there.
        let refused = app_client
            .database("test")
            .run_command(doc! {
                "aggregate": "small",
                "pipeline": [ { "$out": "copy" } ],
                "cursor": {},
            })
            .await;
        assert!(
            refused.is_err(),
            "the read-only role could write: {refused:?}"
        );

        // 7) A database error keeps its own exit code (7) — and the message is
        //    the server's, not a nyet invention.
        let out = run(
            tmp.path(),
            &cfg,
            &[
                "query",
                "mg",
                "db.small.aggregate([{$group: {_id: {$divide: [1, \"x\"]}}}])",
            ],
        );
        assert_eq!(out.status.code(), Some(7), "{}", stdout(&out));
        assert_eq!(envelope(&out)["error"]["code"], "DB_ERROR");

        // 8) A collection that does not exist reads as an EMPTY result, not as
        //    an error: MongoDB has no catalog entry to miss, and that is what
        //    the agent must be told (the honest answer is "no documents").
        let out = run(tmp.path(), &cfg, &["query", "mg", "db.missing.find({})"]);
        assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
        assert_eq!(envelope(&out)["meta"]["row_count"], 0);

        schema_says_what_is_a_schema_and_what_is_a_guess(tmp.path(), &cfg);
        explain_shows_the_plan_without_running_the_query(tmp.path(), &cfg, port);
        doctor_proves_read_only_from_privileges(tmp.path(), port);
        pii_policy_denies_and_masks(tmp.path(), port);
        sample_draws_documents_and_cannot_miss_a_collection(tmp.path(), &cfg, port);

        drop(container);
    });
}

/// `nyet sample` on MongoDB is one `$sample` aggregation — already on the
/// allowlist, and unguarded (this engine's guardrail is `off`), so there is no
/// fallback to reach. What it must still say honestly: zero documents does NOT
/// mean the collection is missing, because MongoDB has no catalog to miss.
fn sample_draws_documents_and_cannot_miss_a_collection(home: &Path, cfg: &Path, port: u16) {
    let out = run(home, cfg, &["sample", "mg", "small"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let v = envelope(&out);
    assert_eq!(v["meta"]["row_count"], 5);
    assert_eq!(v["meta"]["truncated"], false);
    // Documents, so the columns are the union of the top-level field names.
    assert!(v["rows"][0]["name"].is_string(), "{v}");

    let out = run(home, cfg, &["sample", "mg", "small", "--limit", "3"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let v = envelope(&out);
    assert_eq!(v["meta"]["row_count"], 3);
    assert_eq!(v["meta"]["truncated"], true);

    // The one MongoDB answer that would be an error anywhere else.
    let out = run(home, cfg, &["sample", "mg", "no_such_collection"]);
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
    assert_eq!(envelope(&out)["meta"]["row_count"], 0);

    // Net B still judges the documents a sample drew: deny refuses the answer,
    // mask redacts it in place — the value never reaches either stream.
    let deny_cfg = write_config(
        home,
        port,
        "[connections.mg.pii]\ncolumns = [\"validated.email\"]\n",
    );
    let out = run(home, &deny_cfg, &["sample", "mg", "validated"]);
    assert_eq!(out.status.code(), Some(5), "{}", stdout(&out));
    assert_eq!(envelope(&out)["error"]["reason"], "PII_COLUMN");
    assert!(!stdout(&out).contains("a@b.c"), "leaked to stdout");

    let mask_cfg = write_config(
        home,
        port,
        "[connections.mg.pii]\ncolumns = [\"validated.email\"]\nmode = \"mask\"\n",
    );
    let out = run(home, &mask_cfg, &["sample", "mg", "validated"]);
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
    let v = envelope(&out);
    assert_eq!(v["rows"][0]["email"], "[REDACTED]");
    assert!(
        v["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w["code"] == "PII_MASKED"),
        "{v}"
    );
    assert!(!stdout(&out).contains("a@b.c"), "leaked to stdout");
}

/// The `[pii]` policy on a live server (PII-M1): net A refuses a mention, net B
/// refuses a result that carries the field the query never named (deny) or
/// redacts it in place at every depth (mask), and the value never reaches
/// stdout or stderr either way.
fn pii_policy_denies_and_masks(home: &Path, port: u16) {
    // `validated` holds emails; `small` does not (its rule stays dormant).
    let deny_cfg = write_config(
        home,
        port,
        "[connections.mg.pii]\ncolumns = [\"validated.email\"]\n",
    );
    let mask_cfg = write_config(
        home,
        port,
        "[connections.mg.pii]\ncolumns = [\"validated.email\"]\nmode = \"mask\"\n",
    );
    let leak = |out: &Output, what: &str| {
        assert!(!stdout(out).contains("a@b.c"), "{what}: leaked to stdout");
        assert!(!stderr(out).contains("a@b.c"), "{what}: leaked to stderr");
    };

    // Net A: naming the field refuses before execution, in both modes.
    for cfg in [&deny_cfg, &mask_cfg] {
        let out = run(
            home,
            cfg,
            &["query", "mg", "db.validated.find({email: \"a@b.c\"})"],
        );
        assert_eq!(out.status.code(), Some(5), "{}", stdout(&out));
        assert_eq!(envelope(&out)["error"]["reason"], "PII_COLUMN");
        leak(&out, "net A");
    }

    // Net B, deny: `find({})` never names the field, the documents carry it.
    let out = run(home, &deny_cfg, &["query", "mg", "db.validated.find({})"]);
    assert_eq!(out.status.code(), Some(5), "{}", stdout(&out));
    let v = envelope(&out);
    assert_eq!(v["error"]["code"], "NYET");
    assert_eq!(v["error"]["reason"], "PII_COLUMN");
    leak(&out, "net B deny");

    // Net B, mask: the same read succeeds, the value is [REDACTED], and the
    // warning names the field.
    let out = run(
        home,
        &mask_cfg,
        &["query", "mg", "db.validated.find({}).sort({age: -1})"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
    let v = envelope(&out);
    assert_eq!(v["rows"][0]["email"], "[REDACTED]");
    assert!(
        v["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w["code"] == "PII_MASKED"),
        "{v}"
    );
    leak(&out, "net B mask");

    // A projection that excludes the field is the deny-mode way in.
    let out = run(
        home,
        &deny_cfg,
        &["query", "mg", "db.validated.find({}, {age: 1})"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
    leak(&out, "deny with projection");

    // A rule on a collection the query does not read stays out of the way.
    let out = run(
        home,
        &deny_cfg,
        &["query", "mg", "db.small.find({}).limit(2)"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));

    // `nyet schema` marks the protected field on the live catalog.
    let out = run(home, &mask_cfg, &["schema", "mg", "validated"]);
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
    let v = envelope(&out);
    let columns = v["schema"]["tables"][0]["columns"].as_array().unwrap();
    let email = columns.iter().find(|c| c["name"] == "email").unwrap();
    assert_eq!(email["pii"], "mask", "{v}");
}

/// `nyet schema` on a real server: the listing, a collection with a declared
/// validator, one without, and a view — with the provenance of every line.
fn schema_says_what_is_a_schema_and_what_is_a_guess(home: &Path, cfg: &Path) {
    // 1) Without a collection name: names and kinds, one round trip, and a
    //    warning that says why there is nothing more.
    let out = run(home, cfg, &["schema", "mg"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let v = envelope(&out);
    let kinds: Vec<(String, String)> = v["schema"]["tables"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| {
            (
                t["name"].as_str().unwrap().to_string(),
                t["kind"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert!(
        kinds.contains(&("small".to_string(), "collection".to_string())),
        "{v}"
    );
    assert!(
        kinds.contains(&("small_view".to_string(), "view".to_string())),
        "{v}"
    );
    // The internal catalogs layer 1 refuses to read are not advertised either.
    assert!(!kinds.iter().any(|(n, _)| n.starts_with("system.")), "{v}");
    assert!(v["schema"]["tables"][0].get("columns").is_none(), "{v}");
    assert!(
        v["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w["code"] == "SCHEMA_TRUNCATED"),
        "{v}"
    );

    // 2) A collection with a DECLARED validator: those fields are a real rule
    //    the server enforces, and they say so. A field the validator does not
    //    mention is still shown — as the guess it is.
    let out = run(home, cfg, &["schema", "mg", "validated"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let v = envelope(&out);
    let table = &v["schema"]["tables"][0];
    assert_eq!(table["kind"], "collection");
    assert_eq!(table["count"], 2, "the count comes from $collStats: {v}");
    assert_eq!(table["sampled"], 2);
    let column = |name: &str| {
        table["columns"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == name)
            .unwrap_or_else(|| panic!("no {name} column in {v}"))
            .clone()
    };
    assert_eq!(column("email")["source"], "validator");
    assert_eq!(column("email")["type"], "string");
    // A single-column unique index folds into the column flag, as everywhere.
    assert_eq!(column("email")["unique"], true);
    assert_eq!(column("age")["type"], "int|null");
    assert_eq!(column("note")["source"], "sample");
    assert_eq!(column("note")["seen"], 1, "seen in one of the two: {v}");
    assert_eq!(column("_id")["pk"], true);
    // The whole answer carries the marker: part of it is an inference (UX-7).
    let sampled = v["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|w| w["code"] == "SCHEMA_SAMPLED")
        .unwrap_or_else(|| panic!("no SCHEMA_SAMPLED warning in {v}"))
        .clone();
    assert!(sampled["message"].as_str().unwrap().contains("$sample"));

    // 3) A collection with no validator at all: every field is a guess, nested
    //    paths are dotted (the spelling a filter takes), and the document count
    //    is the collection's own.
    let out = run(home, cfg, &["schema", "mg", "small"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let v = envelope(&out);
    let table = &v["schema"]["tables"][0];
    assert_eq!(table["count"], 5);
    let columns = table["columns"].as_array().unwrap();
    assert!(
        columns.iter().all(|c| c["source"] == "sample"),
        "nothing here is a schema: {v}"
    );
    let city = columns
        .iter()
        .find(|c| c["name"] == "profile.city")
        .unwrap_or_else(|| panic!("no dotted path in {v}"));
    assert_eq!(city["type"], "string");
    assert_eq!(city["seen"], 1);
    assert_eq!(
        columns.iter().find(|c| c["name"] == "tags").unwrap()["type"],
        "array"
    );

    // 4) A view is named as a view and sampled like anything else.
    let out = run(home, cfg, &["schema", "mg", "small_view"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let v = envelope(&out);
    assert_eq!(v["schema"]["tables"][0]["kind"], "view");
    assert_eq!(v["schema"]["tables"][0]["sampled"], 5);

    // 5) A collection that is not there is exit 7 with the way forward, like a
    //    missing table on the SQL engines.
    let out = run(home, cfg, &["schema", "mg", "nope"]);
    assert_eq!(out.status.code(), Some(7), "{}", stdout(&out));
    let v = envelope(&out);
    assert_eq!(v["error"]["code"], "DB_ERROR");
    assert!(v["error"]["hint"].as_str().unwrap().contains("nyet schema"));
}

/// `nyet explain`: the plan, no numbers invented — and, the point of the whole
/// command, WITHOUT running the query.
fn explain_shows_the_plan_without_running_the_query(home: &Path, cfg: &Path, port: u16) {
    // An indexed lookup and an unindexed one, which is the difference the
    // agent actually needs (there is no cost number to compare).
    let out = run(
        home,
        cfg,
        &["explain", "mg", "db.validated.find({email: \"a@b.c\"})"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let v = envelope(&out);
    let plan = &v["estimate"]["plan"];
    assert_eq!(plan["namespace"], "test.validated");
    assert!(
        plan["stages"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s.as_str().unwrap().contains("IXSCAN")),
        "{v}"
    );
    assert_eq!(plan["indexes"][0], "email_1");
    assert_eq!(plan["collection_documents"], 2);
    // No cost, no row estimate: MongoDB publishes neither, and nyet does not
    // invent one (the guardrail is off for this engine).
    assert_eq!(v["estimate"]["mode"], "off");
    assert_eq!(v["estimate"]["verdict"], "no_estimate");
    assert!(v["estimate"].get("cost").is_none(), "{v}");
    assert!(v["estimate"].get("rows").is_none(), "{v}");

    let out = run(
        home,
        cfg,
        &["explain", "mg", "db.small.find({name: \"ann\"})"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let v = envelope(&out);
    assert_eq!(v["estimate"]["plan"]["stages"][0], "COLLSCAN");
    assert!(v["estimate"]["plan"].get("indexes").is_none(), "{v}");

    // THE claim: `explain` does not execute. This is the very pipeline that
    // times out under `--timeout 1` when it is RUN (case 4 above); planning it
    // answers in milliseconds, so a success here is the proof.
    let heavy = "db.many.aggregate([{$lookup: {from: \"many\", as: \"x\", let: {v: \"$n\"}, \
                 pipeline: [{$match: {$expr: {$eq: [\"$m\", \"$$v\"]}}}]}}, \
                 {$group: {_id: null, n: {$sum: {$size: \"$x\"}}}}])";
    // The one-second budget is the server's too (maxTimeMS rides on the
    // explain), so a plan that turned into an execution would come back as
    // TIMEOUT (exit 8) instead of a plan. No timing assertion, no flake.
    let second = write_config(home, port, "timeout_secs = 1\n");
    let out = run(home, &second, &["explain", "mg", heavy]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "explain must PLAN, not run: {}",
        stdout(&out)
    );
    assert_eq!(envelope(&out)["estimate"]["plan"]["namespace"], "test.many");
}

/// `nyet doctor`: layer 3 proven from the privileges the server publishes, with
/// no probe write anywhere — and honest about what it could not check.
fn doctor_proves_read_only_from_privileges(home: &Path, port: u16) {
    let json = |cfg: &Path| -> serde_json::Value {
        let out = run(home, cfg, &["doctor", "mg", "--format", "json"]);
        assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
        assert_no_password_leak(&out);
        envelope(&out)
    };

    // The recommended setup: role `read` on this database and nothing else.
    let v = json(&write_config_as(home, port, "app"));
    assert_eq!(check_status(&v, "connectivity"), "ok");
    assert_eq!(check_status(&v, "read_only_role"), "ok", "{v}");
    assert_eq!(check_status(&v, "not_superuser"), "ok", "{v}");
    // Scripting cannot be checked under a read-only role, and doctor says that
    // instead of passing (UX-1) — nyet will not probe by RUNNING JavaScript.
    assert_eq!(check_status(&v, "server_side_js"), "warn", "{v}");
    // Plaintext connection: not a pass either.
    assert_eq!(check_status(&v, "transport_encrypted"), "warn", "{v}");

    // Read here, write in another database of the same cluster: honest warning
    // that names WHERE, because `$out` from here into there is a way out.
    let v = json(&write_config_as(home, port, "app_rw"));
    assert_eq!(check_status(&v, "read_only_role"), "warn", "{v}");
    let message = v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "read_only_role")
        .unwrap()["message"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(message.contains("scratch"), "{message}");

    // And with no server at all: doctor still exits 0 (a broken connection is
    // a diagnosis), and every check that needed the server says so instead of
    // passing. Lives here rather than in tests/cli.rs because a dead MongoDB
    // connect costs ten seconds of server selection, and that gate is the fast
    // one (Д9).
    let dead = home.join("config_dead.toml");
    std::fs::write(
        &dead,
        format!(
            "[connections.mg]\nengine = \"mongodb\"\n\
             url = \"mongodb://nobody@127.0.0.1:1/test\"\n\
             allowed_dirs = [\"{}\"]\ntimeout_secs = 1\n",
            home.display()
        ),
    )
    .unwrap();
    let out = run(home, &dead, &["doctor", "mg", "--format", "json"]);
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
    let v = envelope(&out);
    assert_eq!(check_status(&v, "connectivity"), "fail", "{v}");
    for name in ["read_only_role", "not_superuser", "server_side_js"] {
        assert_eq!(check_status(&v, name), "warn", "{name} must not read as ok");
    }

    // A role scoped to one view: `listCollections` is Unauthorized, so the
    // LISTING still answers (nameOnly + authorizedCollections) and the
    // collection it may not see is simply not there.
    let cfg = write_config_as(home, port, "app_view");
    let v = json(&cfg);
    assert_eq!(check_status(&v, "read_only_role"), "ok", "{v}");
    let out = run(home, &cfg, &["schema", "mg"]);
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
    let v = envelope(&out);
    let tables = v["schema"]["tables"].as_array().unwrap();
    assert_eq!(tables.len(), 1, "only what this role may read: {v}");
    assert_eq!(tables[0]["name"], "small_view");
    // And the view itself can still be described, from a sample alone.
    let out = run(home, &cfg, &["schema", "mg", "small_view"]);
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
    let v = envelope(&out);
    assert_eq!(v["schema"]["tables"][0]["sampled"], 5, "{v}");
    assert!(
        v["schema"]["tables"][0]["columns"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["source"] == "sample"),
        "{v}"
    );
}
