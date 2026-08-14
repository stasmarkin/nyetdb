//! ClickHouse end-to-end (W9): drive the real binary against a throwaway
//! `clickhouse-server` container. Requires a reachable Docker daemon; these
//! tests fail (not skip) without one, like the other engines'.
//!
//! What only a live server can settle, and therefore what this file is for:
//!
//! - layer 2 is real — `readonly = 1` refuses a write that never went through
//!   layer 1 (the direct-engine probe the other engines run too);
//! - the guardrail's number comes from `EXPLAIN ESTIMATE` and nothing is
//!   executed when it is over the limit;
//! - **the account whose profile is already `readonly = 1` still works.** That
//!   one is not a nicety: it is the layer-3 setup nyet recommends, and the
//!   first cut of this engine was broken on exactly it (every url parameter is
//!   a settings change, and an account at readonly = 1 may not make one);
//! - `doctor` tells `readonly = 1` and `readonly = 2` apart, and does not
//!   report the second as the first;
//! - a failed query is never a cheerful empty result — ClickHouse writes the
//!   exception INSIDE a well-formed JSON body, and that must not read as ok.
//!
//! Everything runs in ONE container: starting one costs seconds, and the cases
//! are independent.

use std::path::Path;
use std::process::{Command, Output};
use testcontainers_modules::testcontainers::core::IntoContainerPort;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{ContainerAsync, GenericImage, ImageExt};

/// Digest-pinned like the other stands' images: a future push of this tag must
/// not silently change the server these assertions reason about. Refresh
/// consciously (`docker pull clickhouse/clickhouse-server:24.8-alpine &&
/// docker inspect --format '{{index .RepoDigests 0}}' ...`).
const CH_TAG: &str =
    "24.8-alpine@sha256:b002e56ed5c16e224c312527f6fcba7e77216fec5d7a88a7828f59efc614feb5";

/// A distinctive password so a leak into stdout/stderr is unmistakable.
const PW: &str = "s3cr3t_ch_xyz";
const PW_ENV: &str = "NYET_CH_TEST_PW";

fn multi_thread_rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// One HTTP request straight at the server — the stand's own hands, not nyet's.
/// `user` picks the account, so the seeding runs as `default` while the tests
/// run as the two read-only accounts.
async fn http(port: u16, user: &str, sql: &str) -> String {
    http_maybe(port, user, sql)
        .await
        .expect("connect to clickhouse")
}

/// The same request, but tolerating a server that is not listening yet — the
/// readiness poll and nothing else.
async fn http_maybe(port: u16, user: &str, sql: &str) -> Option<String> {
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .ok()?;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut read, mut write) = stream.into_split();
    // HTTP/1.0 on purpose: 1.1 makes the server answer with `Transfer-Encoding:
    // chunked`, and this helper is a socket and a format string, not an HTTP
    // client — the chunk-size lines would land in the assertions as data.
    let request = format!(
        "POST /?user={user} HTTP/1.0\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\n\r\n{sql}",
        sql.len()
    );
    write.write_all(request.as_bytes()).await.ok()?;
    let mut body = String::new();
    read.read_to_string(&mut body).await.ok()?;
    Some(body)
}

/// Start the server, seed a MergeTree table, and create the two accounts the
/// tests need: `ro` (SELECT + `readonly = 1`, the recommended setup) and `ro2`
/// (SELECT + `readonly = 2`, the one doctor must NOT report as the first).
async fn start_and_seed() -> (ContainerAsync<GenericImage>, u16) {
    // No `WaitFor` log line: this image logs to a FILE inside the container
    // (`/var/log/clickhouse-server/...`), so the only honest readiness signal
    // is the interface answering. Poll `/ping` instead of matching a banner
    // that is not on any stream.
    let container = GenericImage::new("clickhouse/clickhouse-server", CH_TAG)
        .with_exposed_port(8123.tcp())
        .with_env_var("CLICKHOUSE_SKIP_USER_SETUP", "1")
        .start()
        .await
        .expect("start clickhouse-server (is docker/colima running?)");
    let port = container.get_host_port_ipv4(8123).await.unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        if http_maybe(port, "default", "SELECT 1")
            .await
            .is_some_and(|body| body.contains("200 OK"))
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "clickhouse never came up"
        );
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }

    for sql in [
        "CREATE TABLE events (id UInt32, email String, note String) \
         ENGINE = MergeTree ORDER BY id",
        "INSERT INTO events SELECT number, concat('u', toString(number), '@example.com'), 'n' \
         FROM numbers(50000)",
        "CREATE VIEW v_events AS SELECT id, email FROM events",
        &format!(
            "CREATE USER ro IDENTIFIED WITH plaintext_password BY '{PW}' SETTINGS readonly = 1"
        ),
        "GRANT SELECT ON default.* TO ro",
        &format!(
            "CREATE USER ro2 IDENTIFIED WITH plaintext_password BY '{PW}' SETTINGS readonly = 2"
        ),
        "GRANT SELECT ON default.* TO ro2",
    ] {
        let reply = http(port, "default", sql).await;
        assert!(
            !reply.contains("DB::Exception"),
            "seeding failed: {sql}\n{reply}"
        );
    }
    (container, port)
}

fn config(dir: &Path, port: u16, user: &str, extra: &str) -> std::path::PathBuf {
    let path = dir.join("config.toml");
    std::fs::write(
        &path,
        format!(
            r#"
[connections.ch]
engine = "clickhouse"
url = "http://{user}@127.0.0.1:{port}/default"
password = {{ env = "{PW_ENV}" }}
allowed_dirs = ["{}"]
{extra}
"#,
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

fn assert_no_password_leak(out: &Output) {
    assert!(!stdout(out).contains(PW), "password leaked to stdout");
    assert!(!stderr(out).contains(PW), "password leaked to stderr");
}

#[test]
fn clickhouse_end_to_end() {
    multi_thread_rt().block_on(async {
        let (container, port) = start_and_seed().await;
        let tmp = tempfile::tempdir().unwrap();

        // ------------------------------------------------------------------
        // The recommended account: profile readonly = 1, SELECT only.
        // ------------------------------------------------------------------
        let cfg = config(tmp.path(), port, "ro", "");

        // 1) A plain read works AT ALL on this account. The first cut of this
        // engine did not: every url parameter is a settings change, and an
        // account at readonly = 1 may not make one, so nyet's own
        // max_execution_time was refused before a row was read.
        let out = run(
            tmp.path(),
            &cfg,
            &[
                "query",
                "ch",
                "SELECT id, note FROM events ORDER BY id LIMIT 3",
            ],
        );
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        let v = json(&out);
        assert_eq!(v["ok"], true);
        assert_eq!(
            v["rows"],
            serde_json::json!([
                {"id": 0, "note": "n"},
                {"id": 1, "note": "n"},
                {"id": 2, "note": "n"}
            ])
        );
        assert_no_password_leak(&out);

        // 2) A 64-bit integer is a NUMBER, on an account that cannot turn off
        // ClickHouse's default quoting of them. The shape of an answer must not
        // depend on how the DBA configured the role.
        let out = run(
            tmp.path(),
            &cfg,
            &["query", "ch", "SELECT toInt64(9007199254740993) AS big"],
        );
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        assert!(
            stdout(&out).contains("\"big\":9007199254740993"),
            "wide integer came back quoted: {}",
            stdout(&out)
        );

        // 3) The row limit bites, and says so.
        let out = run(
            tmp.path(),
            &cfg,
            &[
                "query",
                "ch",
                "SELECT id FROM events ORDER BY id",
                "--limit",
                "5",
            ],
        );
        let v = json(&out);
        assert_eq!(v["meta"]["row_count"], 5);
        assert_eq!(v["meta"]["truncated"], true);
        assert!(stdout(&out).contains("TRUNCATED"));

        // 4) Layer 1: a write never reaches the server, and the exit code is
        // the refusal's, not the database's.
        for (sql, reason) in [
            ("INSERT INTO events VALUES (1, 'x', 'y')", "WRITE_OPERATION"),
            ("ALTER TABLE events DELETE WHERE id = 1", "PARSE_FAILED"),
            (
                "SELECT * FROM events SETTINGS max_threads = 2",
                "TXN_CONTROL",
            ),
            ("SELECT * FROM events FORMAT JSON", "WIRE_FORMAT"),
            (
                "SELECT * FROM url('http://127.0.0.1:1/x', CSV, 'a String')",
                "DENIED_FUNCTION",
            ),
            (
                "SELECT * FROM cluster('default', system.one)",
                "DENIED_FUNCTION",
            ),
            ("SELECT sleep(3)", "DENIED_FUNCTION"),
        ] {
            let out = run(tmp.path(), &cfg, &["query", "ch", sql]);
            assert_eq!(out.status.code(), Some(5), "{sql}: {}", stdout(&out));
            let v = json(&out);
            assert_eq!(v["error"]["code"], "NYET", "{sql}");
            assert_eq!(v["error"]["reason"], reason, "{sql}");
        }

        // 5) A failure is a failure. ClickHouse writes the exception INSIDE a
        // well-formed JSON body (`"data": [], "rows": 0, "exception": ...`), so
        // a reply that parses is not a reply that succeeded — the one shape a
        // read tool must never report as ok.
        let out = run(
            tmp.path(),
            &cfg,
            &["query", "ch", "SELECT no_such_column FROM events"],
        );
        assert_eq!(out.status.code(), Some(7), "{}", stdout(&out));
        let v = json(&out);
        assert_eq!(v["ok"], false);
        assert_eq!(v["error"]["code"], "DB_ERROR");
        assert!(
            v["error"]["message"]
                .as_str()
                .unwrap()
                .contains("no_such_column"),
            "{v}"
        );

        // 6) schema: tables, views and the sorting key, and no invented pk.
        let out = run(tmp.path(), &cfg, &["schema", "ch"]);
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        let v = json(&out);
        let tables = v["schema"]["tables"].as_array().unwrap();
        let events = tables.iter().find(|t| t["name"] == "events").unwrap();
        assert_eq!(events["kind"], "table");
        assert_eq!(events["indexes"][0]["name"], "ORDER BY");
        assert_eq!(events["indexes"][0]["columns"][0], "id");
        // ClickHouse's sorting key is not a primary key: it does not enforce
        // uniqueness, so nothing here may claim it does.
        assert!(events["columns"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["pk"].is_null() && c["unique"].is_null()));
        let view = tables.iter().find(|t| t["name"] == "v_events").unwrap();
        assert_eq!(view["kind"], "view");

        // 7) explain: the estimate comes from EXPLAIN ESTIMATE, and nothing ran.
        let out = run(
            tmp.path(),
            &cfg,
            &["explain", "ch", "SELECT * FROM events WHERE id > 25000"],
        );
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        let v = json(&out);
        assert_eq!(v["estimate"]["mode"], "rows");
        assert!(v["estimate"]["rows"].as_u64().unwrap() > 0);
        assert!(v["estimate"]["plan"]["estimate"][0]["table"] == "events");

        // 8) doctor on the recommended account: layer 3 proven by a probe the
        // server refuses, and readonly = 1 named as itself.
        let out = run(tmp.path(), &cfg, &["doctor", "ch", "--format", "json"]);
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        let v = json(&out);
        let checks = v["checks"].as_array().unwrap();
        let by = |name: &str| {
            checks
                .iter()
                .find(|c| c["name"] == name)
                .unwrap_or_else(|| panic!("no {name} check in {v}"))
        };
        assert_eq!(by("connectivity")["status"], "ok");
        assert_eq!(by("read_only_role")["status"], "ok");
        assert_eq!(by("not_superuser")["status"], "ok");
        assert_eq!(by("readonly_setting")["status"], "ok");
        assert!(by("readonly_setting")["message"]
            .as_str()
            .unwrap()
            .contains("readonly = 1"));
        assert_no_password_leak(&out);

        // The probe leaves nothing behind.
        let left = http(
            port,
            "default",
            "SELECT groupArray(name) FROM system.tables WHERE name LIKE 'nyet_doctor_probe%'",
        )
        .await;
        assert!(
            left.trim_end().ends_with("[]"),
            "probe table left behind: {left}"
        );

        // ------------------------------------------------------------------
        // 9) readonly = 2 must NOT read as readonly = 1. It refuses writes, so
        // read_only_role is still ok — and that is exactly why this check has
        // to exist: without it the setup would look identical while the client
        // could raise its own limits.
        // ------------------------------------------------------------------
        let cfg2 = config(tmp.path(), port, "ro2", "");
        let out = run(tmp.path(), &cfg2, &["doctor", "ch", "--format", "json"]);
        let v = json(&out);
        let checks = v["checks"].as_array().unwrap();
        let readonly = checks
            .iter()
            .find(|c| c["name"] == "readonly_setting")
            .unwrap();
        assert_eq!(readonly["status"], "warn", "{v}");
        assert!(
            readonly["message"]
                .as_str()
                .unwrap()
                .contains("readonly = 2"),
            "{readonly}"
        );
        assert!(readonly["hint"].as_str().unwrap().contains("readonly = 1"));

        // ------------------------------------------------------------------
        // 10) The guardrail refuses from the plan alone, and executes nothing.
        // ------------------------------------------------------------------
        let cfg3 = config(
            tmp.path(),
            port,
            "ro",
            "[connections.ch.guardrail]\nmode = \"rows\"\nmax_rows = 100\n",
        );
        let out = run(tmp.path(), &cfg3, &["query", "ch", "SELECT * FROM events"]);
        assert_eq!(out.status.code(), Some(5), "{}", stdout(&out));
        let v = json(&out);
        assert_eq!(v["error"]["reason"], "EXPENSIVE_QUERY");
        assert_eq!(v["estimate"]["verdict"], "expensive");
        assert!(v["rows"].is_null(), "a refused query returned rows: {v}");

        drop(container);
    });
}

/// Layer 2 on its own, with layer 1 removed: a write sent straight through the
/// engine, on an account that the SERVER does not stop (the `default`
/// superuser). What refuses it can only be `readonly = 1`, which is the whole
/// claim — and the sharper half is the second case: a table function is not a
/// read to ClickHouse either, so `url()` is refused by the SAME layer that
/// refuses INSERT, not only by nyet's denylist.
#[test]
fn clickhouse_layer2_refuses_what_the_validator_never_saw() {
    multi_thread_rt().block_on(async {
        let (container, port) = start_and_seed().await;
        let engine = nyetdb::engine::Clickhouse {
            url: format!("http://default@127.0.0.1:{port}/default"),
            password: None,
            statement_timeout_ms: 10_000,
            query_timeout_ms: 10_000,
            host_override: None,
            connect_timeout_ms: None,
        };
        use nyetdb::engine::Engine;
        for sql in [
            "INSERT INTO events VALUES (999999, 'x', 'y')",
            "CREATE TABLE bypass (a UInt8) ENGINE = Memory",
            "SELECT * FROM url('http://127.0.0.1:1/x', CSV, 'a String')",
            "SELECT * FROM file('anything.csv')",
        ] {
            let err = engine
                .execute(sql, 10, &nyetdb::guardrail::Guardrail::OFF)
                .await
                .err()
                .unwrap_or_else(|| panic!("layer 2 let this through: {sql}"));
            let text = format!("{err:?}");
            assert!(
                text.contains("readonly") || text.contains("READONLY"),
                "{sql}: refused, but not by layer 2: {text}"
            );
        }
        // Nothing was written by any of the above.
        let count = http(port, "default", "SELECT count() FROM events").await;
        assert!(count.trim_end().ends_with("50000"), "{count}");
        let bypass = http(
            port,
            "default",
            "SELECT groupArray(name) FROM system.tables WHERE name = 'bypass'",
        )
        .await;
        assert!(
            bypass.trim_end().ends_with("[]"),
            "layer 2 let a CREATE through: {bypass}"
        );
        drop(container);
    });
}
