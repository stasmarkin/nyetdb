//! Redis end-to-end (W8): drive the real binary against a throwaway `redis`
//! container. Requires a reachable Docker daemon; these tests fail (not skip)
//! without one, like the other engines'.
//!
//! What only a live server can settle:
//!
//! - **the classification really comes from the server.** The golden corpus
//!   pins the RULE against transcribed flags; this pins that `COMMAND INFO`
//!   says what the corpus claims it says. If a future Redis stops flagging
//!   `GETEX` a write, this is what notices;
//! - the output contract, which is a property of RESP3 replies and not of
//!   nyet's own types: `HGETALL` must come back as field/value pairs, and it
//!   only can because the server sends a typed Map;
//! - `doctor` on an account that may not read its own ACL — the RECOMMENDED
//!   account, and the one the first cut of this engine reported as "could not
//!   verify" instead of proving read-only;
//! - that the probe write leaves nothing behind.
//!
//! Everything runs in ONE container: starting one costs seconds, and the cases
//! are independent.

use std::path::Path;
use std::process::{Command, Output};
use testcontainers_modules::testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{ContainerAsync, GenericImage};

/// Digest-pinned like the other stands' images: a future push of this tag must
/// not silently change the server these assertions reason about.
const REDIS_TAG: &str =
    "7.4-alpine@sha256:e7723ff73d963f5cc6d9c4643ea3d989527a402a319239054e9472a7fb9219a2";

/// A distinctive password so a leak into stdout/stderr is unmistakable.
const PW: &str = "s3cr3t_redis_xyz";
const PW_ENV: &str = "NYET_REDIS_TEST_PW";

fn multi_thread_rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// Start the server and seed one key of every shape the output contract has an
/// opinion about, plus the read-only ACL account.
async fn start_and_seed() -> (ContainerAsync<GenericImage>, u16) {
    let container = GenericImage::new("redis", REDIS_TAG)
        .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
        .with_exposed_port(6379.tcp())
        .start()
        .await
        .expect("start redis (is docker/colima running?)");
    let port = container.get_host_port_ipv4(6379).await.unwrap();
    // The log line is not enough on its own: the published port is not always
    // accepting by the time it appears (measured — a bare connect right after
    // `start()` gets ECONNREFUSED about half the time). Poll the real thing.
    let mut connection = redis_when_ready(port).await;
    for args in [
        vec!["SET", "user:1", "hello"],
        vec!["HSET", "user:42", "name", "Ann", "email", "a@b.c"],
        vec!["RPUSH", "queue:jobs", "a", "b", "c"],
        vec!["SADD", "tags:42", "red"],
        vec!["XADD", "events", "1-1", "f", "v"],
        // The RECOMMENDED account, exactly as the README spells it: no writes,
        // no `acl` (so it cannot read its own rules — that is what doctor's
        // fallback probe is for), and the two metadata commands nyet needs.
        vec![
            "ACL",
            "SETUSER",
            "ro",
            "on",
            ">s3cr3t_redis_xyz",
            "~*",
            "&*",
            "-@all",
            "+@read",
            "+@keyspace",
            "-keys",
            "+command|info",
            "+info",
        ],
        // The same account WITHOUT them — the shape somebody gets by following a
        // generic "read-only Redis user" recipe from anywhere else. `COMMAND` is
        // not in `@read`, so nyet cannot ask what any command does and must
        // refuse every query on it; this is the third instance of the same trap
        // (an engine's recommended hardening breaking the tool) and the reason
        // it is pinned rather than fixed once.
        vec![
            "ACL",
            "SETUSER",
            "ro_bare",
            "on",
            ">s3cr3t_redis_xyz",
            "~*",
            "&*",
            "-@all",
            "+@read",
            "+@keyspace",
        ],
    ] {
        let mut cmd = redis::cmd(args[0]);
        for arg in &args[1..] {
            cmd.arg(*arg);
        }
        let _: redis::Value = cmd.query_async(&mut connection).await.unwrap();
    }
    (container, port)
}

async fn redis_when_ready(port: u16) -> redis::aio::MultiplexedConnection {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        if let Ok(client) = redis::Client::open(format!("redis://127.0.0.1:{port}/0")) {
            if let Ok(connection) = client.get_multiplexed_async_connection().await {
                return connection;
            }
        }
        assert!(std::time::Instant::now() < deadline, "redis never came up");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

async fn redis_client(port: u16, user: Option<&str>) -> redis::aio::MultiplexedConnection {
    let auth = user.map_or_else(String::new, |u| format!("{u}:{PW}@"));
    redis::Client::open(format!("redis://{auth}127.0.0.1:{port}/0"))
        .unwrap()
        .get_multiplexed_async_connection()
        .await
        .unwrap()
}

fn config(dir: &Path, port: u16, user: Option<&str>, extra: &str) -> std::path::PathBuf {
    let path = dir.join("config.toml");
    let (auth, password) = match user {
        Some(u) => (
            format!("{u}@"),
            format!("password = {{ env = \"{PW_ENV}\" }}\n"),
        ),
        None => (String::new(), String::new()),
    };
    std::fs::write(
        &path,
        format!(
            "[connections.r]\nengine = \"redis\"\n\
             url = \"redis://{auth}127.0.0.1:{port}/0\"\n{password}\
             allowed_dirs = [\"{}\"]\n{extra}",
            dir.display()
        ),
    )
    .unwrap();
    path
}

fn run(dir: &Path, cfg: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nyet"))
        .env_clear()
        .env("HOME", dir)
        .env(PW_ENV, PW)
        .current_dir(dir)
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
fn json(out: &Output) -> serde_json::Value {
    serde_json::from_str(stdout(out).trim()).unwrap()
}

#[test]
fn redis_end_to_end() {
    multi_thread_rt().block_on(async {
        let (container, port) = start_and_seed().await;
        let tmp = tempfile::tempdir().unwrap();
        let cfg = config(tmp.path(), port, None, "");

        // 1) The output contract, one case per RESP3 reply type. This is the
        // owner's call from W8 made concrete: the SHAPE of the answer follows
        // the SHAPE of the reply, and nyet keeps no table of which command
        // returns what.
        let out = run(tmp.path(), &cfg, &["query", "r", "GET user:1"]);
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        assert_eq!(json(&out)["rows"], serde_json::json!([{"value": "hello"}]));

        // A Map: two columns. In RESP2 this reply is indistinguishable from
        // LRANGE's, which is exactly why nyet speaks RESP3.
        let out = run(tmp.path(), &cfg, &["query", "r", "HGETALL user:42"]);
        let rows = json(&out)["rows"].as_array().unwrap().clone();
        assert_eq!(rows.len(), 2);
        assert!(rows.contains(&serde_json::json!({"field": "name", "value": "Ann"})));
        assert!(rows.contains(&serde_json::json!({"field": "email", "value": "a@b.c"})));

        let out = run(tmp.path(), &cfg, &["query", "r", "LRANGE queue:jobs 0 -1"]);
        assert_eq!(
            json(&out)["rows"],
            serde_json::json!([{"value": "a"}, {"value": "b"}, {"value": "c"}])
        );

        // A scalar integer stays a number, and a nil stays null.
        let out = run(tmp.path(), &cfg, &["query", "r", "EXISTS nope"]);
        assert_eq!(json(&out)["rows"], serde_json::json!([{"value": 0}]));
        let out = run(tmp.path(), &cfg, &["query", "r", "GET nope"]);
        assert_eq!(json(&out)["rows"], serde_json::json!([{"value": null}]));

        // A nested element keeps its structure in the cell: nyet does not know
        // that a stream entry is an id plus a field list, so it does not invent
        // columns for one.
        let out = run(tmp.path(), &cfg, &["query", "r", "XRANGE events - +"]);
        assert_eq!(
            json(&out)["rows"],
            serde_json::json!([{"value": ["1-1", ["f", "v"]]}])
        );

        // 2) The classification is the SERVER's, and this is where that claim
        // is checked against a live one. Every refusal below is exit 5 with a
        // NYET reason — a refusal, not a database error.
        for (command, reason) in [
            ("SET k v", "WRITE_OPERATION"),
            // The W7 class: reads with a side effect. Redis flags GETEX a write
            // itself ("because it changes the TTL") — nyet keeps no list.
            ("GETEX user:1 EX 60", "WRITE_OPERATION"),
            ("GETDEL user:1", "WRITE_OPERATION"),
            ("SPOP tags:42", "WRITE_OPERATION"),
            ("SORT queue:jobs", "WRITE_OPERATION"),
            ("FLUSHALL", "WRITE_OPERATION"),
            // Flagged neither read nor write: nyet was not told, so it refuses.
            ("SUBSCRIBE news", "WRITE_OPERATION"),
            ("INFO", "WRITE_OPERATION"),
            ("NOSUCHCOMMAND x", "WRITE_OPERATION"),
            // Administrative, blocking, @dangerous.
            ("CONFIG GET requirepass", "DENIED_COMMAND"),
            ("DEBUG SLEEP 5", "DENIED_COMMAND"),
            ("BLPOP queue:jobs 0", "WRITE_OPERATION"),
            ("XREAD BLOCK 0 STREAMS events $", "DENIED_COMMAND"),
            ("KEYS *", "DENIED_COMMAND"),
            // Scripting: refused although the server calls EVAL_RO a read.
            ("EVAL_RO \"return 1\" 0", "DENIED_COMMAND"),
            ("FCALL_RO f 0", "DENIED_COMMAND"),
            // The parser, before any of that.
            ("GET \"unterminated", "PARSE_FAILED"),
        ] {
            let out = run(tmp.path(), &cfg, &["query", "r", command]);
            assert_eq!(out.status.code(), Some(5), "{command}: {}", stdout(&out));
            let v = json(&out);
            assert_eq!(v["error"]["code"], "NYET", "{command}");
            assert_eq!(v["error"]["reason"], reason, "{command}");
        }
        // Nothing above changed anything.
        let mut connection = redis_client(port, None).await;
        let value: Option<String> = redis::cmd("GET")
            .arg("user:1")
            .query_async(&mut connection)
            .await
            .unwrap();
        assert_eq!(
            value.as_deref(),
            Some("hello"),
            "a refused command still ran"
        );

        // 3) `allow_functions` reaches the POLICY refusals and stops at the
        // hard one. A read-only tool that can be configured into writing is not
        // a read-only tool.
        let permissive = config(
            tmp.path(),
            port,
            None,
            "[connections.r.validator]\nallow_functions = [\"info\", \"keys\", \"set\"]\n",
        );
        let out = run(tmp.path(), &permissive, &["query", "r", "INFO server"]);
        assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
        let out = run(tmp.path(), &permissive, &["query", "r", "KEYS user:*"]);
        assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
        let out = run(tmp.path(), &permissive, &["query", "r", "SET k v"]);
        assert_eq!(out.status.code(), Some(5), "{}", stdout(&out));
        assert!(json(&out)["error"]["message"]
            .as_str()
            .unwrap()
            .contains("as a write"));

        // 4) The row limit truncates and says so. Redis has no LIMIT, so the
        // count is nyet's — and SECURITY.md records that the whole reply
        // reached this process before it was counted.
        let out = run(
            tmp.path(),
            &cfg,
            &["query", "r", "LRANGE queue:jobs 0 -1", "--limit", "2"],
        );
        let v = json(&out);
        assert_eq!(v["meta"]["row_count"], 2);
        assert_eq!(v["meta"]["truncated"], true);

        // 5) `schema` is `na`, and it says so in the PAYLOAD — `tables: []` on
        // its own reads as "an empty database", which is a different claim.
        let out = run(tmp.path(), &cfg, &["schema", "r"]);
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        let v = json(&out);
        assert_eq!(v["schema"]["tables"], serde_json::json!([]));
        assert!(v["schema"]["na"].as_str().unwrap().contains("no schema"));
        let db0 = &v["schema"]["databases"][0];
        assert_eq!(db0["name"], "db0");
        assert!(db0["keys"].as_u64().unwrap() >= 4, "{v}");

        // 6) `explain` has nothing to show — and still runs layer 1, so it can
        // never be the way past the classifier.
        let out = run(tmp.path(), &cfg, &["explain", "r", "GET user:1"]);
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        assert_eq!(json(&out)["estimate"]["verdict"], "no_estimate");
        let out = run(tmp.path(), &cfg, &["explain", "r", "FLUSHALL"]);
        assert_eq!(out.status.code(), Some(5), "{}", stdout(&out));
        assert_eq!(json(&out)["error"]["reason"], "WRITE_OPERATION");

        // 7) `sample` has no meaning here and says so rather than inventing one.
        let out = run(tmp.path(), &cfg, &["sample", "r", "user"]);
        assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
        assert_eq!(json(&out)["error"]["code"], "NOT_IMPLEMENTED");

        // 8) `[pii]` is refused at CONFIG PARSE. A policy that reads as
        // protection and protects nothing is the worst kind of lie, and a Redis
        // reply has no column for a `table.column` rule to key on.
        let with_pii = config(
            tmp.path(),
            port,
            None,
            "[connections.r.pii]\ncolumns = [\"users.email\"]\n",
        );
        let out = run(tmp.path(), &with_pii, &["query", "r", "GET user:1"]);
        assert_eq!(out.status.code(), Some(3), "{}", stdout(&out));
        assert_eq!(json(&out)["error"]["code"], "CONFIG_INVALID");

        drop(container);
    });
}

/// `doctor` against the RECOMMENDED account: a read-only ACL user that may not
/// read its own ACL rules (`acl` lives in @admin). The first cut of this engine
/// reported "could not verify" for exactly that setup, which makes the check
/// useless where it matters most; the fallback is a probe write that expires by
/// itself.
#[test]
fn redis_doctor_proves_layer_three_on_an_account_that_cannot_read_its_own_acl() {
    multi_thread_rt().block_on(async {
        let (container, port) = start_and_seed().await;
        let tmp = tempfile::tempdir().unwrap();

        // The permissive default account: layer 3 is NOT in place, and doctor
        // must say so rather than shrug.
        let cfg = config(tmp.path(), port, None, "");
        let out = run(tmp.path(), &cfg, &["doctor", "r", "--format", "json"]);
        let v = json(&out);
        let by = |v: &serde_json::Value, name: &str| {
            v["checks"]
                .as_array()
                .unwrap()
                .iter()
                .find(|c| c["name"] == name)
                .unwrap_or_else(|| panic!("no {name} check in {v}"))
                .clone()
        };
        assert_eq!(by(&v, "read_only_role")["status"], "fail", "{v}");
        assert_eq!(by(&v, "not_superuser")["status"], "fail", "{v}");
        // The missing layer is NAMED. Every other engine has a layer 2; saying
        // nothing here would let its absence pass unmentioned.
        assert_eq!(by(&v, "read_only_session")["status"], "na");
        assert!(by(&v, "read_only_session")["message"]
            .as_str()
            .unwrap()
            .contains("no read-only session"));

        // The recommended account, and the first thing to check about it is
        // that it can be USED: a query, not just a diagnosis.
        let cfg = config(tmp.path(), port, Some("ro"), "");
        let out = run(tmp.path(), &cfg, &["query", "r", "GET user:1"]);
        assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
        assert_eq!(json(&out)["rows"], serde_json::json!([{"value": "hello"}]));
        let out = run(tmp.path(), &cfg, &["query", "r", "SET k v"]);
        assert_eq!(out.status.code(), Some(5), "{}", stdout(&out));
        let out = run(tmp.path(), &cfg, &["schema", "r"]);
        assert!(
            json(&out)["schema"]["databases"][0]["keys"]
                .as_u64()
                .unwrap()
                >= 4
        );

        let out = run(tmp.path(), &cfg, &["doctor", "r", "--format", "json"]);
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        let v = json(&out);
        assert_eq!(by(&v, "connectivity")["status"], "ok", "{v}");
        assert_eq!(by(&v, "read_only_session")["status"], "na", "{v}");
        assert_eq!(by(&v, "read_only_role")["status"], "ok", "{v}");
        // Not "could not verify": an account that may not run ACL WHOAMI
        // provably does not hold +@all, which includes it.
        assert_eq!(by(&v, "not_superuser")["status"], "ok", "{v}");
        assert!(!stdout(&out).contains(PW), "password leaked to stdout");
        assert!(!stderr(&out).contains(PW), "password leaked to stderr");

        // An account WITHOUT `+command|info` cannot be served at all, and the
        // check that exists to say what stands in for layer 2 is where that has
        // to surface — `na` there would be a green light on a connection where
        // every query fails.
        let cfg = config(tmp.path(), port, Some("ro_bare"), "");
        let out = run(tmp.path(), &cfg, &["doctor", "r", "--format", "json"]);
        let v = json(&out);
        assert_eq!(by(&v, "read_only_session")["status"], "fail", "{v}");
        assert!(by(&v, "read_only_session")["hint"]
            .as_str()
            .unwrap()
            .contains("+command|info"));
        // ...and the query refusal is its OWN reason, because no rewrite fixes it.
        let out = run(tmp.path(), &cfg, &["query", "r", "GET user:1"]);
        assert_eq!(out.status.code(), Some(5), "{}", stdout(&out));
        assert_eq!(json(&out)["error"]["reason"], "UNCLASSIFIED");
        // `schema` still answers — the honest answer to "what is the schema" is
        // `na` with or without the key counts — and says why they are missing
        // rather than letting an absent `databases` read as an empty key space.
        let out = run(tmp.path(), &cfg, &["schema", "r"]);
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        let v = json(&out);
        assert!(v["schema"]["databases"].is_null(), "{v}");
        assert!(v["schema"]["na"]
            .as_str()
            .unwrap()
            .contains("may not run INFO"));

        // The probe leaves nothing behind — it carries EX 1 and NX, so even a
        // probe that LANDED would expire on its own.
        let mut connection = redis_client(port, None).await;
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg("nyet_doctor_probe*")
            .query_async(&mut connection)
            .await
            .unwrap();
        assert!(keys.is_empty(), "probe key left behind: {keys:?}");

        drop(container);
    });
}
