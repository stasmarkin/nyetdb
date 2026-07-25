//! MySQL/MariaDB end-to-end: drive the real binary against a throwaway
//! mariadb:11.4 container (testcontainers + Docker/colima). Requires a reachable
//! Docker daemon; these tests fail (not skip) without one, so CI with a docker
//! service runs them. Pins exit codes and envelope structure (Д7).
//!
//! MariaDB is the e2e flavor because its default `mysql_native_password` auth
//! works over the plaintext loopback — MySQL 8's default `caching_sha2_password`
//! needs client-side RSA (feature `mysql-rsa`, which pulls the RSA crate flagged
//! by RUSTSEC-2023-0071) or TLS, neither of which this build ships (see README).
//! So this test also exercises the `engine = "mariadb"` path: the server timeout
//! is `max_statement_time` (seconds) and its SQLSTATE (1969) maps to TIMEOUT.
//! The MySQL path (real JSON type, `max_execution_time`, 3024) is covered by the
//! `mysql_layer2_types_and_timeout` engine test.

use std::path::Path;
use std::process::{Command, Output};
use testcontainers_modules::mariadb::Mariadb;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt};

/// A distinctive password so a leak into stdout/stderr is unmistakable.
const PW: &str = "s3cr3t_pw_xyz";
const PW_ENV: &str = "NYET_MYSQL_TEST_PW";

fn multi_thread_rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// Start mariadb:11.4 (preloaded locally), seed a small table, and create a
/// passworded application user (mysql_native_password, works over plaintext).
/// Returns the container (kept alive by the caller) + host port.
async fn start_and_seed() -> (ContainerAsync<Mariadb>, u16) {
    let container = Mariadb::default()
        .with_tag("11.4")
        .start()
        .await
        .expect("start mariadb:11.4 (is docker/colima running?)");
    let port = container.get_host_port_ipv4(3306).await.unwrap();

    use sqlx::{ConnectOptions, Connection, Executor};
    let opts: sqlx::mysql::MySqlConnectOptions = format!("mysql://root@127.0.0.1:{port}/test")
        .parse()
        .unwrap();
    let mut w = opts.connect().await.unwrap();
    w.execute("CREATE TABLE users (id int primary key, email varchar(255))")
        .await
        .unwrap();
    w.execute("INSERT INTO users VALUES (1, 'a@b.c'), (2, 'd@e.f'), (3, NULL)")
        .await
        .unwrap();
    let create_user = format!("CREATE USER 'app'@'%' IDENTIFIED BY '{PW}'");
    w.execute(sqlx::AssertSqlSafe(create_user)).await.unwrap();
    w.execute("GRANT ALL PRIVILEGES ON *.* TO 'app'@'%'")
        .await
        .unwrap();
    w.execute("FLUSH PRIVILEGES").await.unwrap();
    w.close().await.unwrap();
    (container, port)
}

fn write_mysql_config(dir: &Path, port: u16) -> std::path::PathBuf {
    let path = dir.join("config.toml");
    std::fs::write(
        &path,
        format!(
            "[connections.my]\nengine = \"mariadb\"\n\
             url = \"mysql://app@127.0.0.1:{port}/test\"\n\
             password_env = \"{PW_ENV}\"\nallowed_dirs = [\"{}\"]\n",
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

fn assert_no_password_leak(out: &Output) {
    assert!(!stdout(out).contains(PW), "password leaked to stdout");
    assert!(!stderr(out).contains(PW), "password leaked to stderr");
}

#[test]
fn mysql_query_end_to_end() {
    multi_thread_rt().block_on(async {
        let (container, port) = start_and_seed().await;
        let tmp = tempfile::tempdir().unwrap();
        let cfg = write_mysql_config(tmp.path(), port);

        // 1) Successful SELECT, json envelope on stdout.
        let out = run(
            tmp.path(),
            &cfg,
            &["query", "my", "SELECT id, email FROM users ORDER BY id"],
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
        assert_eq!(v["meta"]["connection"], "my");
        assert_no_password_leak(&out);

        // 2) table format: data on stdout, envelope on stderr.
        let out = run(
            tmp.path(),
            &cfg,
            &[
                "query",
                "my",
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
                "my",
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
            &["query", "my", "SELECT * FROM no_such_table"],
        );
        assert_eq!(out.status.code(), Some(7), "{}", stdout(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["error"]["code"], "DB_ERROR");
        assert_no_password_leak(&out);

        // 5) timeout: a heavy cross join cancelled by the server
        // max_statement_time (MariaDB) or the outer tokio timeout -> exit 8.
        // sleep()/benchmark() are denylisted, so use a big information_schema
        // cross join.
        let out = run(
            tmp.path(),
            &cfg,
            &[
                "query",
                "my",
                "SELECT count(*) FROM information_schema.columns a, \
                 information_schema.columns b, information_schema.columns c",
                "--timeout",
                "1",
            ],
        );
        assert_eq!(out.status.code(), Some(8), "{}", stdout(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["error"]["code"], "TIMEOUT");

        // 6) a write is refused by the validator before any connection (exit 5).
        let out = run(tmp.path(), &cfg, &["query", "my", "DELETE FROM users"]);
        assert_eq!(out.status.code(), Some(5));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["error"]["code"], "NYET");
        assert_eq!(v["error"]["reason"], "WRITE_OPERATION");

        container.rm().await.unwrap();
    });
}

#[test]
fn mysql_connection_failed_is_exit_6() {
    // No server on this port -> the connection is refused -> CONNECTION_FAILED.
    let tmp = tempfile::tempdir().unwrap();
    let cfg = write_mysql_config(tmp.path(), 59998);
    let out = run(
        tmp.path(),
        &cfg,
        &["query", "my", "SELECT 1", "--timeout", "5"],
    );
    assert_eq!(out.status.code(), Some(6), "{}", stdout(&out));
    let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
    assert_eq!(v["error"]["code"], "CONNECTION_FAILED");
    assert_no_password_leak(&out);
}
