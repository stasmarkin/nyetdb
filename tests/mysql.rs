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
