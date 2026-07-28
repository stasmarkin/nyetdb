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

/// Config for the container, optionally with extra sections (a `[guardrail]`).
/// Each variant gets its own file name so several can coexist in one temp dir.
fn write_mysql_config_with(dir: &Path, port: u16, extra: &str) -> std::path::PathBuf {
    let path = dir.join(format!("config{}.toml", extra.len()));
    std::fs::write(
        &path,
        format!(
            "[connections.my]\nengine = \"mariadb\"\n\
             url = \"mysql://app@127.0.0.1:{port}/test\"\n\
             password_env = \"{PW_ENV}\"\nallowed_dirs = [\"{}\"]\n{extra}",
            dir.display()
        ),
    )
    .unwrap();
    path
}

fn write_mysql_config(dir: &Path, port: u16) -> std::path::PathBuf {
    write_mysql_config_with(dir, port, "")
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
        // The guardrail is turned off for this one case: whether it stops such
        // a query depends on what the server estimates for information_schema
        // (which is not the behavior under test here), and the timeout path must
        // be exercised deterministically.
        let unguarded = write_mysql_config_with(
            tmp.path(),
            port,
            "[connections.my.guardrail]\nmode = \"off\"\n",
        );
        let out = run(
            tmp.path(),
            &unguarded,
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

/// `nyet schema` against a real MariaDB: AUTO_INCREMENT, a composite primary
/// key, a composite foreign key, a single-column UNIQUE and a view. Only the
/// connection's own database is introspected (`DATABASE()`), so the server's
/// system schemas never show up.
#[test]
fn mysql_schema_end_to_end() {
    multi_thread_rt().block_on(async {
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
        for ddl in [
            "CREATE TABLE orgs (id bigint NOT NULL AUTO_INCREMENT PRIMARY KEY, \
             name varchar(100) NOT NULL UNIQUE) ENGINE=InnoDB",
            "CREATE TABLE orders (org_id bigint NOT NULL, seq int NOT NULL, note text, \
             PRIMARY KEY (org_id, seq)) ENGINE=InnoDB",
            "CREATE TABLE order_lines (org_id bigint NOT NULL, seq int NOT NULL, \
             sku varchar(64), qty int DEFAULT 1, KEY order_lines_sku_idx (sku), \
             CONSTRAINT ol_fk FOREIGN KEY (org_id, seq) REFERENCES orders(org_id, seq)) \
             ENGINE=InnoDB",
            "CREATE VIEW v_orgs AS SELECT id, name FROM orgs",
            // A foreign key into another database: the parent must keep it.
            "CREATE DATABASE other",
            "CREATE TABLE other.parent (id bigint NOT NULL PRIMARY KEY) ENGINE=InnoDB",
            "CREATE TABLE child (pid bigint, CONSTRAINT child_fk FOREIGN KEY (pid) \
             REFERENCES other.parent(id)) ENGINE=InnoDB",
            // A column-level grant: STATISTICS/KEY_COLUMN_USAGE are NOT
            // privilege-filtered by the server, so the composite pk and the
            // index over the ungranted column are the leak to close.
            "CREATE TABLE pt (a int NOT NULL, b int NOT NULL, PRIMARY KEY (a, b), \
             KEY pt_b_idx (b), KEY pt_a_idx (a)) ENGINE=InnoDB",
            &format!("CREATE USER 'app'@'%' IDENTIFIED BY '{PW}'"),
            "GRANT ALL PRIVILEGES ON *.* TO 'app'@'%'",
            &format!("CREATE USER 'partial'@'%' IDENTIFIED BY '{PW}'"),
            "GRANT SELECT (a) ON test.pt TO 'partial'@'%'",
            "FLUSH PRIVILEGES",
        ] {
            w.execute(sqlx::AssertSqlSafe(ddl.to_string()))
                .await
                .unwrap();
        }
        w.close().await.unwrap();

        let tmp = tempfile::tempdir().unwrap();
        let cfg = write_mysql_config(tmp.path(), port);

        let out = run(tmp.path(), &cfg, &["schema", "my"]);
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        assert_no_password_leak(&out);
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["meta"]["table_count"], 6, "{v}");
        let tables = v["schema"]["tables"].as_array().unwrap();
        // Only the connection's own database — `other.parent` is not listed.
        let names: Vec<&str> = tables.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(
            names,
            ["child", "order_lines", "orders", "orgs", "pt", "v_orgs"]
        );
        // ...but a foreign key INTO it keeps the database qualifier, the way
        // PostgreSQL qualifies a parent outside `public`.
        assert_eq!(
            tables[0]["fks"],
            serde_json::json!([{"columns": ["pid"], "ref_table": "other.parent",
                                "ref_columns": ["id"]}])
        );

        // AUTO_INCREMENT is reported as the column default (MySQL keeps it in
        // EXTRA, not COLUMN_DEFAULT); the single-column UNIQUE folds into a flag.
        let orgs = &tables[3];
        assert_eq!(orgs["columns"][0]["name"], "id");
        assert_eq!(orgs["columns"][0]["pk"], true);
        assert_eq!(orgs["columns"][0]["nullable"], false);
        assert_eq!(orgs["columns"][0]["default"], "auto_increment");
        assert!(
            orgs["columns"][0]["type"]
                .as_str()
                .unwrap()
                .starts_with("bigint"),
            "{orgs}"
        );
        assert_eq!(orgs["columns"][1]["unique"], true);
        assert!(orgs.get("indexes").is_none(), "{orgs}");

        // Composite primary key on both members, its index not repeated.
        assert_eq!(tables[2]["columns"][0]["pk"], true);
        assert_eq!(tables[2]["columns"][1]["pk"], true);
        assert!(tables[2].get("indexes").is_none(), "{}", tables[2]);

        // Composite foreign key, ordered.
        assert_eq!(
            tables[1]["fks"],
            serde_json::json!([{
                "columns": ["org_id", "seq"],
                "ref_table": "orders",
                "ref_columns": ["org_id", "seq"]
            }])
        );
        // The plain index is there (InnoDB also indexes the fk columns).
        let indexes = tables[1]["indexes"].as_array().unwrap();
        assert!(
            indexes.iter().any(|i| i["name"] == "order_lines_sku_idx"
                && i["columns"] == serde_json::json!(["sku"])),
            "{indexes:?}"
        );
        assert_eq!(tables[1]["columns"][3]["default"], "1");

        // A view: columns, no indexes/fks.
        assert_eq!(tables[5]["kind"], "view");
        assert!(tables[5]["columns"].is_array());
        assert!(tables[5].get("indexes").is_none());
        // With full privileges nothing is filtered: pt keeps its composite pk
        // and both indexes (contrast with the column-granted account below).
        assert_eq!(tables[4]["columns"][0]["pk"], true);
        assert_eq!(tables[4]["columns"][1]["pk"], true);
        assert_eq!(tables[4]["indexes"].as_array().unwrap().len(), 2);

        // One table, and the not-found path (exit 7).
        let out = run(tmp.path(), &cfg, &["schema", "my", "orders"]);
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["meta"]["table_count"], 1);
        assert_eq!(v["schema"]["tables"][0]["name"], "orders");
        for arg in ["nope", "orders; DROP TABLE orgs", "orgs'--"] {
            let out = run(tmp.path(), &cfg, &["schema", "my", arg]);
            assert_eq!(out.status.code(), Some(7), "{arg}: {}", stdout(&out));
            let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
            assert_eq!(v["error"]["code"], "DB_ERROR", "{arg}");
        }

        // The same server through a COLUMN-granted account: information_schema
        // hands out the keys over `b` anyway, so nyet must drop them — a pk
        // shown as `a` alone would be a wrong schema, and `b` a leaked name.
        let partial_cfg = tmp.path().join("partial.toml");
        std::fs::write(
            &partial_cfg,
            format!(
                "[connections.my]\nengine = \"mariadb\"\n\
                 url = \"mysql://partial@127.0.0.1:{port}/test\"\n\
                 password_env = \"{PW_ENV}\"\nallowed_dirs = [\"{}\"]\n",
                tmp.path().display()
            ),
        )
        .unwrap();
        let out = run(tmp.path(), &partial_cfg, &["schema", "my"]);
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        let body = stdout(&out);
        let v: serde_json::Value = serde_json::from_str(body.trim()).unwrap();
        assert_eq!(v["meta"]["table_count"], 1, "{v}");
        let pt = &v["schema"]["tables"][0];
        assert_eq!(pt["name"], "pt");
        assert_eq!(pt["columns"].as_array().unwrap().len(), 1, "{pt}");
        assert_eq!(pt["columns"][0]["name"], "a");
        assert!(pt["columns"][0].get("pk").is_none(), "{pt}");
        // Only the keys touching `b` are gone; the index over the granted
        // column stays (the filter drops keys, not the whole section).
        assert_eq!(
            pt["indexes"],
            serde_json::json!([{"name": "pt_a_idx", "columns": ["a"]}]),
            "{pt}"
        );
        for leak in ["pt_b_idx", "\"b\""] {
            assert!(!body.contains(leak), "leaked {leak}: {body}");
        }
        assert_no_password_leak(&out);

        container.rm().await.unwrap();
    });
}

/// `nyet doctor` against a real MariaDB: the hybrid layer-3 check (metadata + a
/// write probe with layer 2 removed). The `app` account holds `ALL PRIVILEGES ON
/// *.*`, so it FAILS both read_only_role (the probe writes) and not_superuser; a
/// SELECT-only account passes both. The probe (a create-then-drop, since MySQL
/// DDL auto-commits) is proven to leave NO table behind and touch no data.
#[test]
fn mysql_doctor_end_to_end() {
    multi_thread_rt().block_on(async {
        let (container, port) = start_and_seed().await;
        let tmp = tempfile::tempdir().unwrap();

        // A SELECT-only account: its probe CREATE is refused (no CREATE priv).
        use sqlx::{ConnectOptions, Connection, Executor};
        let opts: sqlx::mysql::MySqlConnectOptions = format!("mysql://root@127.0.0.1:{port}/test")
            .parse()
            .unwrap();
        let mut w = opts.connect().await.unwrap();
        w.execute(sqlx::AssertSqlSafe(format!(
            "CREATE USER 'ro'@'%' IDENTIFIED BY '{PW}'"
        )))
        .await
        .unwrap();
        w.execute("GRANT SELECT ON test.* TO 'ro'@'%'")
            .await
            .unwrap();
        w.execute("FLUSH PRIVILEGES").await.unwrap();
        w.close().await.unwrap();

        let by = |v: &serde_json::Value, name: &str| {
            v["checks"]
                .as_array()
                .unwrap()
                .iter()
                .find(|c| c["name"] == name)
                .unwrap_or_else(|| panic!("no {name}: {v}"))
                .clone()
        };

        // 1) The `app` account holds ALL PRIVILEGES ON *.*: it can write and is
        // an admin, so both layer-3 checks FAIL — exit 0 regardless.
        let cfg = write_mysql_config(tmp.path(), port);
        let out = run(tmp.path(), &cfg, &["doctor", "my", "--format", "json"]);
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        assert_no_password_leak(&out);
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(by(&v, "connectivity")["status"], "ok");
        assert_eq!(by(&v, "read_only_role")["status"], "fail", "{v}");
        assert!(by(&v, "read_only_role")["hint"]
            .as_str()
            .unwrap()
            .contains("CREATE USER 'nyet_ro'"));
        assert_eq!(by(&v, "not_superuser")["status"], "fail", "{v}");
        assert_eq!(by(&v, "transport_encrypted")["status"], "warn", "{v}");
        // The raw SHOW GRANTS line is never echoed (MariaDB can embed a password
        // hash after `IDENTIFIED BY PASSWORD`): only the privilege type is named.
        // (The read-only-role hint's own `IDENTIFIED BY '...'` template is fine —
        // the leak form is `IDENTIFIED BY PASSWORD '*hash'`.)
        assert!(
            !stdout(&out).contains("IDENTIFIED BY PASSWORD"),
            "{}",
            stdout(&out)
        );

        // 2) The probe left NO table behind and did not touch the data.
        let opts: sqlx::mysql::MySqlConnectOptions = format!("mysql://root@127.0.0.1:{port}/test")
            .parse()
            .unwrap();
        let mut c = opts.connect().await.unwrap();
        let probes: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM information_schema.TABLES \
             WHERE TABLE_NAME LIKE 'nyet_doctor_probe_%'",
        )
        .fetch_one(&mut c)
        .await
        .unwrap();
        assert_eq!(probes, 0, "the probe table must not survive");
        let users: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
            .fetch_one(&mut c)
            .await
            .unwrap();
        assert_eq!(users, 3, "the probe must not touch real data");
        c.close().await.unwrap();

        // 3) The SELECT-only account: the server refuses its probe write, so
        // read_only_role is OK and it is not an admin.
        let ro = tmp.path().join("ro.toml");
        std::fs::write(
            &ro,
            format!(
                "[connections.my]\nengine = \"mariadb\"\n\
                 url = \"mysql://ro@127.0.0.1:{port}/test\"\n\
                 password_env = \"{PW_ENV}\"\nallowed_dirs = [\"{}\"]\n",
                tmp.path().display()
            ),
        )
        .unwrap();
        let out = run(tmp.path(), &ro, &["doctor", "my", "--format", "json"]);
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(by(&v, "read_only_role")["status"], "ok", "{v}");
        assert!(by(&v, "read_only_role").get("hint").is_none(), "{v}");
        assert_eq!(by(&v, "not_superuser")["status"], "ok", "{v}");

        // 4) ORPHAN REPORTING: an account with CREATE but NOT DROP writes the
        // probe table (auto-committed) and then cannot drop it. The orphan must
        // be REPORTED with its name (forensics), never left silently.
        let opts: sqlx::mysql::MySqlConnectOptions = format!("mysql://root@127.0.0.1:{port}/test")
            .parse()
            .unwrap();
        let mut c = opts.connect().await.unwrap();
        c.execute(sqlx::AssertSqlSafe(format!(
            "CREATE USER 'nodrop'@'%' IDENTIFIED BY '{PW}'"
        )))
        .await
        .unwrap();
        c.execute("GRANT SELECT, CREATE ON test.* TO 'nodrop'@'%'")
            .await
            .unwrap();
        c.execute("FLUSH PRIVILEGES").await.unwrap();
        c.close().await.unwrap();

        let nodrop = tmp.path().join("nodrop.toml");
        std::fs::write(
            &nodrop,
            format!(
                "[connections.my]\nengine = \"mariadb\"\n\
                 url = \"mysql://nodrop@127.0.0.1:{port}/test\"\n\
                 password_env = \"{PW_ENV}\"\nallowed_dirs = [\"{}\"]\n",
                tmp.path().display()
            ),
        )
        .unwrap();
        let out = run(tmp.path(), &nodrop, &["doctor", "my", "--format", "json"]);
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        // The role can write -> fail, and the leftover probe name is surfaced.
        assert_eq!(by(&v, "read_only_role")["status"], "fail", "{v}");
        let msg = by(&v, "read_only_role")["message"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(msg.contains("nyet_doctor_probe_"), "{msg}");
        // The orphan is REAL: a table by that name actually remains.
        let opts: sqlx::mysql::MySqlConnectOptions = format!("mysql://root@127.0.0.1:{port}/test")
            .parse()
            .unwrap();
        let mut c = opts.connect().await.unwrap();
        let orphans: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM information_schema.TABLES \
             WHERE TABLE_NAME LIKE 'nyet_doctor_probe_%'",
        )
        .fetch_one(&mut c)
        .await
        .unwrap();
        assert_eq!(orphans, 1, "the reported orphan must actually exist");
        c.close().await.unwrap();
        // The throwaway container is dropped next, taking the orphan with it.

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

/// A functional key part (`INDEX ((lower(a)), b)`) is reported as
/// `(expression)` instead of vanishing — a dropped part would make this
/// two-part unique index look single-column and fold into a `unique` flag on
/// `b` that does not exist. MySQL 8, not MariaDB: only MySQL has functional
/// indexes (root over plaintext loopback with an empty password — fast auth).
#[test]
fn mysql8_functional_index_key_part_is_not_dropped() {
    use testcontainers_modules::mysql::Mysql;

    multi_thread_rt().block_on(async {
        let container = Mysql::default()
            .with_tag("8.4")
            .start()
            .await
            .expect("start mysql:8.4 (is docker/colima running?)");
        let port = container.get_host_port_ipv4(3306).await.unwrap();

        use sqlx::{ConnectOptions, Connection, Executor};
        let opts: sqlx::mysql::MySqlConnectOptions = format!("mysql://root@127.0.0.1:{port}/test")
            .parse()
            .unwrap();
        let mut w = opts.connect().await.unwrap();
        w.execute("CREATE TABLE f (a varchar(50), b varchar(50))")
            .await
            .unwrap();
        w.execute("CREATE UNIQUE INDEX f_expr_idx ON f ((lower(a)), b)")
            .await
            .unwrap();
        // A column-granted account for the accepted-leak check below (MySQL 8
        // needs TLS for a passworded caching_sha2_password user).
        w.execute(sqlx::AssertSqlSafe(format!(
            "CREATE USER 'partial'@'%' IDENTIFIED BY '{PW}'"
        )))
        .await
        .unwrap();
        w.execute("GRANT SELECT (b) ON test.f TO 'partial'@'%'")
            .await
            .unwrap();
        w.close().await.unwrap();

        let tmp = tempfile::tempdir().unwrap();
        let cfg = tmp.path().join("config.toml");
        std::fs::write(
            &cfg,
            format!(
                "[connections.my]\nengine = \"mysql\"\n\
                 url = \"mysql://root@127.0.0.1:{port}/test\"\nallowed_dirs = [\"{}\"]\n",
                tmp.path().display()
            ),
        )
        .unwrap();

        let out = run(tmp.path(), &cfg, &["schema", "my", "f"]);
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        let table = &v["schema"]["tables"][0];
        assert_eq!(
            table["indexes"],
            serde_json::json!([{"name": "f_expr_idx", "columns": ["(expression)", "b"],
                                "unique": true}]),
            "{table}"
        );
        assert!(
            table["columns"][1].get("unique").is_none(),
            "b must not claim a key it does not have: {table}"
        );

        // ACCEPTED LEAK (documented in the README): with only `GRANT SELECT
        // (b)`, column `a` is hidden — but the functional index over it stays
        // visible, because its expression part carries no text to leak. Its
        // NAME can still hint at the hidden column; identifiers only, no data.
        let partial_cfg = tmp.path().join("partial.toml");
        std::fs::write(
            &partial_cfg,
            format!(
                "[connections.my]\nengine = \"mysql\"\n\
                 url = \"mysql://partial@127.0.0.1:{port}/test?ssl-mode=REQUIRED\"\n\
                 password_env = \"{PW_ENV}\"\nallowed_dirs = [\"{}\"]\n",
                tmp.path().display()
            ),
        )
        .unwrap();
        let out = run(tmp.path(), &partial_cfg, &["schema", "my", "f"]);
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        let table = &v["schema"]["tables"][0];
        assert_eq!(
            table["columns"],
            serde_json::json!([{"name": "b", "type": "varchar(50)", "nullable": true}]),
            "{table}"
        );
        assert_eq!(
            table["indexes"],
            serde_json::json!([{"name": "f_expr_idx", "columns": ["(expression)", "b"],
                                "unique": true}]),
            "{table}"
        );

        container.rm().await.unwrap();
    });
}

/// The guardrail on the MySQL/MariaDB side: `rows` mode against the classic
/// EXPLAIN, plus `nyet explain`. Nothing here depends on timing — the monster is
/// a cross join whose row product the planner reports up front.
#[test]
fn mysql_guardrail_and_explain_end_to_end() {
    multi_thread_rt().block_on(async {
        let (container, port) = start_and_seed().await;
        // A table big enough that joining it with itself exceeds the DEFAULT
        // row ceiling (4000 x 4000 = 1.6e7 > 1e7) while each side alone is an
        // ordinary, allowed scan. seq_1_to_N is MariaDB's built-in generator.
        {
            use sqlx::{ConnectOptions, Connection, Executor};
            let opts: sqlx::mysql::MySqlConnectOptions =
                format!("mysql://root@127.0.0.1:{port}/test")
                    .parse()
                    .unwrap();
            let mut w = opts.connect().await.unwrap();
            w.execute("CREATE TABLE big (id int primary key, note varchar(20))")
                .await
                .unwrap();
            w.execute("INSERT INTO big SELECT seq, 'x' FROM seq_1_to_4000")
                .await
                .unwrap();
            w.close().await.unwrap();
        }
        let tmp = tempfile::tempdir().unwrap();
        let cfg = write_mysql_config(tmp.path(), port);

        // 1) Defaults (rows, 1e7): an ordinary read is untouched...
        let out = run(
            tmp.path(),
            &cfg,
            &["query", "my", "SELECT * FROM big LIMIT 5"],
        );
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        assert!(
            !stdout(&out).contains("GUARDRAIL_SKIPPED"),
            "{}",
            stdout(&out)
        );

        // 2) ...and the cross-join monster is refused before it runs.
        let monster = "SELECT count(*) FROM big a CROSS JOIN big b WHERE a.note = b.note";
        let out = run(tmp.path(), &cfg, &["query", "my", monster]);
        assert_eq!(out.status.code(), Some(5), "{}", stdout(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["error"]["code"], "NYET");
        assert_eq!(v["error"]["reason"], "EXPENSIVE_QUERY");
        assert_eq!(v["estimate"]["mode"], "rows");
        assert_eq!(v["estimate"]["verdict"], "expensive");
        assert_eq!(v["estimate"]["threshold"], 10_000_000u64);
        assert!(v["estimate"]["rows"].as_u64().unwrap() > 10_000_000, "{v}");
        // No cost on this engine — it publishes none, so nyet reports none.
        assert!(v["estimate"].get("cost").is_none(), "{v}");
        // The plan travels as one object per EXPLAIN row.
        assert!(v["estimate"]["plan"][0]["table"].is_string(), "{v}");
        assert!(v["error"]["hint"]
            .as_str()
            .unwrap()
            .contains("[connections.my.guardrail] max_rows"));
        assert_no_password_leak(&out);

        // 3) A configured threshold decides deterministically...
        let tiny = write_mysql_config_with(
            tmp.path(),
            port,
            "[connections.my.guardrail]\nmax_rows = 1\n",
        );
        let out = run(tmp.path(), &tiny, &["query", "my", "SELECT * FROM users"]);
        assert_eq!(out.status.code(), Some(5), "{}", stdout(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["error"]["reason"], "EXPENSIVE_QUERY");
        assert_eq!(v["estimate"]["threshold"], 1u64);
        // ...and `off` really is off: the same query runs.
        let off = write_mysql_config_with(
            tmp.path(),
            port,
            "[connections.my.guardrail]\nmode = \"off\"\n",
        );
        let out = run(tmp.path(), &off, &["query", "my", "SELECT * FROM users"]);
        assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));

        // 4) A cost mode this engine cannot honor is a loud config error, never
        // a silent "unguarded" (the message says what it does support).
        let bad = write_mysql_config_with(
            tmp.path(),
            port,
            "[connections.my.guardrail]\nmode = \"cost\"\n",
        );
        let out = run(tmp.path(), &bad, &["query", "my", "SELECT 1"]);
        assert_eq!(out.status.code(), Some(3), "{}", stdout(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["error"]["code"], "CONFIG_INVALID");
        assert!(
            v["error"]["message"].as_str().unwrap().contains("rows"),
            "{v}"
        );

        // 5) A tableless plan ("No tables used") is a KNOWN trivial plan, not an
        // unreadable one: no spurious "could not check" warning.
        let out = run(tmp.path(), &cfg, &["query", "my", "SELECT 1 AS n"]);
        assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
        assert!(
            !stdout(&out).contains("GUARDRAIL_SKIPPED"),
            "{}",
            stdout(&out)
        );

        // 6) REGRESSION GUARD: a role that may SELECT a view but has no rights
        // on the tables under it. `EXPLAIN` over a view can need SHOW VIEW
        // (MySQL raises ER 1345), and the guardrail must never turn a query
        // that WOULD succeed into an error — a guard that breaks working
        // queries is worse than no guard. On mariadb:11.4 the EXPLAIN turns out
        // to be allowed, so the query simply succeeds; where it is not, the
        // best-effort path drops the estimate and warns instead (unit-tested in
        // src/engine.rs). Either way: exit 0 with the rows.
        {
            use sqlx::{ConnectOptions, Connection, Executor};
            let opts: sqlx::mysql::MySqlConnectOptions =
                format!("mysql://root@127.0.0.1:{port}/test")
                    .parse()
                    .unwrap();
            let mut w = opts.connect().await.unwrap();
            w.execute("CREATE VIEW v_users AS SELECT id, email FROM users")
                .await
                .unwrap();
            for grant in [
                format!("CREATE USER 'viewer'@'%' IDENTIFIED BY '{PW}'"),
                "GRANT SELECT ON test.v_users TO 'viewer'@'%'".to_string(),
                "FLUSH PRIVILEGES".to_string(),
            ] {
                w.execute(sqlx::AssertSqlSafe(grant)).await.unwrap();
            }
            w.close().await.unwrap();
        }
        let view_only = tmp.path().join("viewer.toml");
        std::fs::write(
            &view_only,
            format!(
                "[connections.my]\nengine = \"mariadb\"\n\
                 url = \"mysql://viewer@127.0.0.1:{port}/test\"\n\
                 password_env = \"{PW_ENV}\"\nallowed_dirs = [\"{}\"]\n",
                tmp.path().display()
            ),
        )
        .unwrap();
        let out = run(
            tmp.path(),
            &view_only,
            &["query", "my", "SELECT * FROM v_users"],
        );
        assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["meta"]["row_count"], 3, "{v}");

        // 6b) The guardrail lends its EXPLAIN a SHORTER server-side cap and puts
        // the query's own back afterwards. Without the cap an abandoned EXPLAIN
        // keeps running and its late error lands on the NEXT statement; without
        // the restore the query would inherit the 5s guardrail budget. The
        // session variable is observable, so assert it directly: with
        // --timeout 10 the query must see 10 seconds, not the budget.
        let out = run(
            tmp.path(),
            &cfg,
            &[
                "query",
                "my",
                "SELECT @@max_statement_time AS t",
                "--timeout",
                "10",
            ],
        );
        assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(
            v["rows"][0]["t"], 10.0,
            "the query's own cap is restored: {v}"
        );

        // 7) nyet explain: plan + informational verdict, nothing executed.
        let out = run(
            tmp.path(),
            &cfg,
            &["explain", "my", "SELECT id FROM users WHERE id = 1"],
        );
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["estimate"]["mode"], "rows");
        assert_eq!(v["estimate"]["verdict"], "ok");
        assert!(v["estimate"]["plan"][0]["select_type"].is_string(), "{v}");
        assert_eq!(v["meta"]["connection"], "my");
        let out = run(tmp.path(), &cfg, &["explain", "my", monster]);
        assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["estimate"]["verdict"], "expensive");
        assert_no_password_leak(&out);

        container.rm().await.unwrap();
    });
}

/// The PII policy against a live MariaDB (step PII-1): net A by name, net B by
/// the driver's column provenance, and the withheld database error. The view
/// behavior is the measured fact behind the documented limitation.
#[test]
fn mysql_pii_policy_end_to_end() {
    multi_thread_rt().block_on(async {
        let (container, port) = start_and_seed().await;
        const VALUE: &str = "alice@example.com";
        {
            use sqlx::{ConnectOptions, Connection, Executor};
            let opts: sqlx::mysql::MySqlConnectOptions =
                format!("mysql://root@127.0.0.1:{port}/test")
                    .parse()
                    .unwrap();
            let mut w = opts.connect().await.unwrap();
            for sql in [
                format!("INSERT INTO users VALUES (9, '{VALUE}')"),
                "CREATE TABLE orders (id int primary key, uid int, amount int)".to_string(),
                "INSERT INTO orders VALUES (1, 9, 42)".to_string(),
                "CREATE TABLE dict (id int, email varchar(255), note varchar(255))".to_string(),
                format!("INSERT INTO dict VALUES (9, '{VALUE}', 'x')"),
                "CREATE VIEW v_users AS SELECT id, email AS contact FROM users".to_string(),
            ] {
                w.execute(sqlx::AssertSqlSafe(sql)).await.unwrap();
            }
            w.close().await.unwrap();
        }
        let tmp = tempfile::tempdir().unwrap();
        let cfg = write_mysql_config_with(
            tmp.path(),
            port,
            "[connections.my.pii]\ncolumns = [\"users.email\"]\n",
        );
        let no_leak = |out: &Output, sql: &str| {
            assert!(!stdout(out).contains(VALUE), "{sql}: leaked to stdout");
            assert!(!stderr(out).contains(VALUE), "{sql}: leaked to stderr");
        };

        for sql in [
            "SELECT email FROM users",
            "SELECT u.email FROM users u",
            "SELECT `email` FROM `users`",
            "SELECT * FROM users",
            "SELECT count(*) FROM users WHERE email LIKE 'a%'",
            "SELECT * FROM information_schema.column_statistics",
            // finding 3: the USING / NATURAL join oracle.
            "SELECT count(*) FROM users JOIN dict USING (email)",
            "SELECT count(*) FROM users NATURAL JOIN dict",
            // round 2, finding A: `TABLE t` as the right operand of a set
            // operation used to switch net A off completely.
            "SELECT NULL AS a, NULL AS b, NULL AS c UNION ALL TABLE users",
            // round 2, finding B: the parenthesised join.
            "SELECT count(*) FROM (users JOIN dict USING (email))",
            "SELECT count(*) FROM (users NATURAL JOIN dict)",
        ] {
            let out = run(tmp.path(), &cfg, &["query", "my", sql]);
            assert_eq!(out.status.code(), Some(5), "{sql}: {}", stdout(&out));
            let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
            assert_eq!(v["error"]["reason"], "PII_COLUMN", "{sql}");
            no_leak(&out, sql);
            assert_no_password_leak(&out);
        }

        // Net B does not fire on legitimate reads: MySQL/MariaDB report
        // `db.table` + the original column name on the wire, for free.
        for sql in [
            "SELECT id FROM users ORDER BY id",
            "SELECT count(*) AS n FROM users",
            "SELECT * FROM orders",
            "SELECT id, amount FROM orders WHERE 1 = 0",
            "SHOW TABLES",
            "SELECT 1 AS one",
            // finding 9: the wildcard's own source carries no rules.
            "SELECT * FROM orders WHERE uid IN (SELECT id FROM users)",
            "SELECT o.* FROM orders o JOIN users u ON u.id = o.uid",
            "SELECT count(*) FROM users JOIN dict USING (id)",
            // round 2, findings D/E/F.
            "SELECT * FROM (SELECT id FROM users) t",
            "SELECT o.uid FROM orders o JOIN users u ON u.id = o.uid",
            "SELECT amount FROM orders AS users",
        ] {
            let out = run(tmp.path(), &cfg, &["query", "my", sql]);
            // NET B LIVENESS: blinded origins arrive as Unknown, which net B
            // refuses as PII_UNPROVABLE (exit 5) — this line goes red then.
            assert_eq!(out.status.code(), Some(0), "{sql}: {}", stdout(&out));
            no_leak(&out, sql);
        }

        // The raw database error is withheld on a PII connection.
        let out = run(
            tmp.path(),
            &cfg,
            &["query", "my", "SELECT nosuchcol FROM orders"],
        );
        assert_eq!(out.status.code(), Some(7), "{}", stdout(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["error"]["code"], "DB_ERROR");
        let message = v["error"]["message"].as_str().unwrap();
        assert!(message.contains("withheld"), "{message}");
        assert!(!message.contains("nosuchcol"), "{message}");

        // Measured limitation: MariaDB reports a VIEW column's origin as the
        // view (`test.v_users`.`contact`), not the base table — so a rule on
        // `users.email` does not cover it, and the view must be listed.
        let out = run(
            tmp.path(),
            &cfg,
            &["query", "my", "SELECT contact FROM v_users"],
        );
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        assert!(
            stdout(&out).contains(VALUE),
            "the documented view limitation changed: {}",
            stdout(&out)
        );
        let cfg_view = write_mysql_config_with(
            tmp.path(),
            port,
            "[connections.my.pii]\ncolumns = [\"users.email\", \"v_users.contact\"]\n",
        );
        let out = run(
            tmp.path(),
            &cfg_view,
            &["query", "my", "SELECT contact FROM v_users"],
        );
        assert_eq!(out.status.code(), Some(5), "{}", stdout(&out));
        no_leak(&out, "SELECT contact FROM v_users (view listed)");

        // No [pii] section -> byte-for-byte the old behavior.
        let plain = write_mysql_config(tmp.path(), port);
        let out = run(
            tmp.path(),
            &plain,
            &["query", "my", "SELECT email FROM users ORDER BY id"],
        );
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        assert!(stdout(&out).contains(VALUE), "{}", stdout(&out));
        let out = run(
            tmp.path(),
            &plain,
            &["query", "my", "SELECT nosuchcol FROM orders"],
        );
        assert_eq!(out.status.code(), Some(7));
        assert!(stdout(&out).contains("nosuchcol"), "{}", stdout(&out));

        container.rm().await.unwrap();
    });
}

/// `mode = "mask"` against a live MariaDB: the redaction rides on the origin the
/// driver reports on the wire (`db.table` + the ORIGINAL column name, so an
/// alias cannot hide it). Plus the leak guard and the `pii_columns` doctor check
/// against two real accounts — one granted the column, one not.
#[test]
fn mysql_pii_mask_end_to_end() {
    multi_thread_rt().block_on(async {
        let (container, port) = start_and_seed().await;
        const VALUE: &str = "alice@example.com";
        {
            use sqlx::{ConnectOptions, Connection, Executor};
            let opts: sqlx::mysql::MySqlConnectOptions =
                format!("mysql://root@127.0.0.1:{port}/test")
                    .parse()
                    .unwrap();
            let mut w = opts.connect().await.unwrap();
            for sql in [
                format!("INSERT INTO users VALUES (9, '{VALUE}')"),
                "CREATE TABLE dict (id int, email varchar(255))".to_string(),
                // Two accounts: one that may read the protected column (so nyet
                // is the only boundary) and one whose column grant means the
                // server enforces the same line.
                format!("CREATE USER 'pii_all'@'%' IDENTIFIED BY '{PW}'"),
                "GRANT SELECT ON test.users TO 'pii_all'@'%'".to_string(),
                format!("CREATE USER 'pii_none'@'%' IDENTIFIED BY '{PW}'"),
                "GRANT SELECT (id) ON test.users TO 'pii_none'@'%'".to_string(),
                // A column whose name needs quoting: the doctor probe is the one
                // place a config name reaches SQL text, so the escaping has to
                // be exercised by a test, not just by review.
                "ALTER TABLE users ADD COLUMN `we``ird` varchar(8)".to_string(),
                "FLUSH PRIVILEGES".to_string(),
            ] {
                w.execute(sqlx::AssertSqlSafe(sql)).await.unwrap();
            }
            w.close().await.unwrap();
        }
        let tmp = tempfile::tempdir().unwrap();
        let cfg = write_mysql_config_with(
            tmp.path(),
            port,
            "[connections.my.pii]\ncolumns = [\"users.email\"]\nmode = \"mask\"\n\
             [audit]\nlog_responses = true\n",
        );
        let no_leak = |out: &Output, sql: &str| {
            assert!(!stdout(out).contains(VALUE), "{sql}: leaked to stdout");
            assert!(!stderr(out).contains(VALUE), "{sql}: leaked to stderr");
        };

        let sql = "SELECT id, email FROM users";
        let out = run(tmp.path(), &cfg, &["query", "my", sql]);
        assert_eq!(out.status.code(), Some(0), "{sql}: {}", stdout(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        let rows = v["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 4, "{v}");
        for row in rows {
            // The NULL row (id 3) reads exactly like the rest.
            assert_eq!(row["email"], "[REDACTED]", "{v}");
        }
        assert_eq!(v["warnings"][0]["code"], "PII_MASKED", "{v}");
        no_leak(&out, sql);
        assert_no_password_leak(&out);

        // LEAK GUARD: the forensic log holds what the agent saw, masked.
        let audit = tmp.path().join(".local/share/nyet/audit.jsonl");
        let text = std::fs::read_to_string(&audit).expect("audit file must exist");
        assert!(!text.contains(VALUE), "the audit log leaked the value");
        assert!(text.contains("[REDACTED]"), "{text}");

        // The oracles stay refused, mode or no mode.
        for sql in [
            "SELECT count(*) FROM users WHERE email LIKE 'a%'",
            "SELECT email FROM users ORDER BY 1",
            "SELECT DISTINCT email FROM users",
            "SELECT email AS x FROM users",
            "SELECT * FROM users",
            "SELECT count(*) FROM users JOIN dict USING (email)",
            "SELECT NULL AS a, NULL AS b UNION ALL TABLE users",
            "SELECT * FROM information_schema.column_statistics",
        ] {
            let out = run(tmp.path(), &cfg, &["query", "my", sql]);
            assert_eq!(out.status.code(), Some(5), "{sql}: {}", stdout(&out));
            let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
            assert_eq!(v["error"]["reason"], "PII_COLUMN", "{sql}");
            no_leak(&out, sql);
        }

        // doctor, against the two real accounts.
        let doctor_pii = |user: &str| {
            let cfg = tmp.path().join(format!("doctor-{user}.toml"));
            std::fs::write(
                &cfg,
                format!(
                    "[connections.my]\nengine = \"mariadb\"\n\
                     url = \"mysql://{user}@127.0.0.1:{port}/test\"\n\
                     password_env = \"{PW_ENV}\"\nallowed_dirs = [\"{}\"]\n\
                     [connections.my.pii]\ncolumns = [\"users.email\"]\nmode = \"mask\"\n",
                    tmp.path().display()
                ),
            )
            .unwrap();
            let out = run(tmp.path(), &cfg, &["doctor", "my", "--format", "json"]);
            assert_eq!(out.status.code(), Some(0), "{user}: {}", stderr(&out));
            let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
            v["checks"]
                .as_array()
                .unwrap()
                .iter()
                .find(|c| c["name"] == "pii_columns")
                .unwrap_or_else(|| panic!("{user}: no pii_columns check: {v}"))
                .clone()
        };
        let check = doctor_pii("pii_all");
        assert_eq!(check["status"], "warn", "{check}");
        assert!(
            check["message"].as_str().unwrap().contains("users.email"),
            "{check}"
        );
        // information_schema.COLUMNS is privilege-filtered by the server, so the
        // column-granted account provably cannot see `email` at all — but an
        // INVISIBLE column is ambiguous there ("not granted" vs "no such
        // column"), which is why the verdict comes from the server's error code
        // (1143 denied vs 1054 unknown). Both directions, on one account:
        let check = doctor_pii("pii_none");
        assert_eq!(check["status"], "ok", "{check}");

        // The probe's identifier quoting (a doubled backtick) is load-bearing:
        // without it this rule produces a syntax error instead of the server's
        // "denied" code, and a real column-level grant would read as
        // "could not verify" — the ablation that used to pass unnoticed.
        let cfg_quoted = tmp.path().join("doctor-quoted.toml");
        std::fs::write(
            &cfg_quoted,
            format!(
                "[connections.my]\nengine = \"mariadb\"\n\
                 url = \"mysql://pii_none@127.0.0.1:{port}/test\"\n\
                 password_env = \"{PW_ENV}\"\nallowed_dirs = [\"{}\"]\n\
                 [connections.my.pii]\ncolumns = ['\"users\".\"we`ird\"']\n",
                tmp.path().display()
            ),
        )
        .unwrap();
        let out = run(
            tmp.path(),
            &cfg_quoted,
            &["doctor", "my", "--format", "json"],
        );
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        let check = v["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "pii_columns")
            .unwrap();
        assert_eq!(check["status"], "ok", "{check}");
        // A rule naming a column that does not exist protects NOTHING, and must
        // never read as "the database enforces it" (it did, before review).
        let cfg_typo = tmp.path().join("doctor-typo.toml");
        std::fs::write(
            &cfg_typo,
            format!(
                "[connections.my]\nengine = \"mariadb\"\n\
                 url = \"mysql://pii_none@127.0.0.1:{port}/test\"\n\
                 password_env = \"{PW_ENV}\"\nallowed_dirs = [\"{}\"]\n\
                 [connections.my.pii]\ncolumns = [\"users.nosuchcolumn\"]\n",
                tmp.path().display()
            ),
        )
        .unwrap();
        let out = run(tmp.path(), &cfg_typo, &["doctor", "my", "--format", "json"]);
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        let check = v["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "pii_columns")
            .unwrap();
        assert_eq!(check["status"], "warn", "{check}");
        assert!(
            check["message"]
                .as_str()
                .unwrap()
                .contains("could not verify"),
            "{check}"
        );

        container.rm().await.unwrap();
    });
}

/// `nyet sample` against a real MariaDB: the ordinary answer, and a table name
/// that only survives as a BACKQUOTED identifier — the proof that the argument
/// is a name and not a fragment of SQL.
#[test]
fn mysql_sample_end_to_end() {
    multi_thread_rt().block_on(async {
        let (container, port) = start_and_seed().await;
        {
            use sqlx::{ConnectOptions, Connection, Executor};
            let opts: sqlx::mysql::MySqlConnectOptions =
                format!("mysql://root@127.0.0.1:{port}/test")
                    .parse()
                    .unwrap();
            let mut w = opts.connect().await.unwrap();
            // A space and a reserved word: unquoted, this is a syntax error.
            w.execute("CREATE TABLE `odd order` (id int, v varchar(10))")
                .await
                .unwrap();
            w.execute("INSERT INTO `odd order` VALUES (1, 'x'), (2, 'y')")
                .await
                .unwrap();
            w.close().await.unwrap();
        }
        let tmp = tempfile::tempdir().unwrap();
        let cfg = write_mysql_config(tmp.path(), port);

        let out = run(tmp.path(), &cfg, &["sample", "my", "users"]);
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        assert_no_password_leak(&out);
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["meta"]["row_count"], 3);
        assert_eq!(v["meta"]["truncated"], false);
        assert!(v["rows"][0].get("email").is_some(), "{v}");

        let out = run(
            tmp.path(),
            &cfg,
            &["sample", "my", "odd order", "--limit", "1"],
        );
        assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["meta"]["row_count"], 1);
        assert_eq!(v["meta"]["truncated"], true);

        // A name that matches nothing is a database error with a hint about
        // the name — the agent never wrote the statement.
        let out = run(tmp.path(), &cfg, &["sample", "my", "nope"]);
        assert_eq!(out.status.code(), Some(7), "{}", stdout(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["error"]["code"], "DB_ERROR");
        assert!(
            v["error"]["hint"]
                .as_str()
                .unwrap()
                .contains("nyet schema my"),
            "{v}"
        );

        container.rm().await.unwrap();
    });
}
