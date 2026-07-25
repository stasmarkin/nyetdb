//! PostgreSQL end-to-end: drive the real binary against a throwaway Postgres
//! container (testcontainers + Docker/colima). Requires a reachable Docker
//! daemon; these tests fail (not skip) without one, so CI with a docker
//! service runs them. Pins exit codes and envelope structure (Д7).

use std::path::Path;
use std::process::{Command, Output};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt};

/// A distinctive password so a leak into stdout/stderr is unmistakable
/// (unlike the default "postgres", which also names the user and database).
const PW: &str = "s3cr3t_pw_xyz";
const PW_ENV: &str = "NYET_PG_TEST_PW";

fn multi_thread_rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// Start postgres:16-alpine (preloaded locally) with a known password, seed a
/// small table, and return the container (kept alive by the caller) + host
/// port.
async fn start_and_seed() -> (ContainerAsync<Postgres>, u16) {
    let container = Postgres::default()
        .with_password(PW)
        .with_tag("16-alpine")
        .start()
        .await
        .expect("start postgres:16-alpine (is docker/colima running?)");
    let port = container.get_host_port_ipv4(5432).await.unwrap();

    use sqlx::{ConnectOptions, Connection, Executor};
    let opts: sqlx::postgres::PgConnectOptions =
        format!("postgres://postgres@127.0.0.1:{port}/postgres")
            .parse()
            .unwrap();
    let mut w = opts.password(PW).connect().await.unwrap();
    w.execute("CREATE TABLE users (id int primary key, email text)")
        .await
        .unwrap();
    w.execute("INSERT INTO users VALUES (1, 'a@b.c'), (2, 'd@e.f'), (3, NULL)")
        .await
        .unwrap();
    w.close().await.unwrap();
    (container, port)
}

fn write_pg_config(dir: &Path, port: u16) -> std::path::PathBuf {
    let path = dir.join("config.toml");
    std::fs::write(
        &path,
        format!(
            "[connections.pg]\nengine = \"postgres\"\n\
             url = \"postgres://postgres@127.0.0.1:{port}/postgres\"\n\
             password_env = \"{PW_ENV}\"\nallowed_dirs = [\"{}\"]\n",
            dir.display()
        ),
    )
    .unwrap();
    path
}

/// Run the binary with a clean environment plus HOME and the password env var.
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

/// The password must never appear in either stream (threat model).
fn assert_no_password_leak(out: &Output) {
    assert!(!stdout(out).contains(PW), "password leaked to stdout");
    assert!(!stderr(out).contains(PW), "password leaked to stderr");
}

#[test]
fn postgres_query_end_to_end() {
    // The whole body runs inside block_on: the binary calls are blocking std
    // Command (fine on a multi-thread runtime), and the container's async Drop
    // must run inside the runtime — even if an assertion unwinds.
    multi_thread_rt().block_on(async {
        let (container, port) = start_and_seed().await;
        let tmp = tempfile::tempdir().unwrap();
        let cfg = write_pg_config(tmp.path(), port);

        // 1) Successful SELECT, json envelope on stdout.
        let out = run(
            tmp.path(),
            &cfg,
            &["query", "pg", "SELECT id, email FROM users ORDER BY id"],
        );
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(
            v["rows"],
            serde_json::json!([
                {"id": 1, "email": "a@b.c"},
                {"id": 2, "email": "d@e.f"},
                {"id": 3, "email": null}
            ])
        );
        assert_eq!(v["meta"]["row_count"], 3);
        assert_eq!(v["meta"]["connection"], "pg");
        assert_no_password_leak(&out);

        // 2) table format: data on stdout, envelope on stderr.
        let out = run(
            tmp.path(),
            &cfg,
            &[
                "query",
                "pg",
                "SELECT id, email FROM users ORDER BY id",
                "--format",
                "table",
            ],
        );
        assert_eq!(out.status.code(), Some(0));
        assert!(stdout(&out).starts_with("id  email\n"), "{}", stdout(&out));
        let env: serde_json::Value =
            serde_json::from_str(stderr(&out).trim().lines().last().unwrap()).unwrap();
        assert_eq!(env["meta"]["row_count"], 3);
        assert_no_password_leak(&out);

        // 3) row-limit truncation.
        let out = run(
            tmp.path(),
            &cfg,
            &[
                "query",
                "pg",
                "SELECT id FROM users ORDER BY id",
                "--limit",
                "2",
            ],
        );
        assert_eq!(out.status.code(), Some(0));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["meta"]["row_count"], 2);
        assert_eq!(v["meta"]["truncated"], true);
        assert_eq!(v["warnings"][0]["code"], "TRUNCATED");

        // 4) DB_ERROR: unknown table -> exit 7.
        let out = run(
            tmp.path(),
            &cfg,
            &["query", "pg", "SELECT * FROM no_such_table"],
        );
        assert_eq!(out.status.code(), Some(7), "{}", stdout(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["error"]["code"], "DB_ERROR");
        assert_no_password_leak(&out);

        // 5) timeout: a heavy scan cancelled by the server statement_timeout ->
        // exit 8. pg_sleep is denylisted, so use a huge generate_series scan.
        let out = run(
            tmp.path(),
            &cfg,
            &[
                "query",
                "pg",
                "SELECT count(*) FROM generate_series(1, 100000000000) g",
                "--timeout",
                "1",
            ],
        );
        assert_eq!(out.status.code(), Some(8), "{}", stdout(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["error"]["code"], "TIMEOUT");

        // 6) a write is refused by the validator before any connection (exit 5).
        let out = run(tmp.path(), &cfg, &["query", "pg", "DELETE FROM users"]);
        assert_eq!(out.status.code(), Some(5));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["error"]["code"], "NYET");
        assert_eq!(v["error"]["reason"], "WRITE_OPERATION");

        // Remove the container inside the runtime (its async Drop would panic if
        // it ran after block_on returned).
        container.rm().await.unwrap();
    });
}

#[test]
fn postgres_connection_failed_is_exit_6() {
    // No server on this port -> the connection is refused -> CONNECTION_FAILED.
    let tmp = tempfile::tempdir().unwrap();
    // Port 59999 is almost certainly closed; a refused connect returns fast.
    let cfg = write_pg_config(tmp.path(), 59999);
    let out = run(
        tmp.path(),
        &cfg,
        &["query", "pg", "SELECT 1", "--timeout", "5"],
    );
    assert_eq!(out.status.code(), Some(6), "{}", stdout(&out));
    let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
    assert_eq!(v["error"]["code"], "CONNECTION_FAILED");
    assert_no_password_leak(&out);
}
