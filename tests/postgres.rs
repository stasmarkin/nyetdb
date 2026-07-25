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

/// `nyet schema` against a real PostgreSQL: a non-public schema (qualified
/// names), a view, a materialized view, a composite primary key and a composite
/// foreign key, a `serial` default, a partial unique index, colliding display
/// names, and the qualified/unqualified/case-folded `[table]` argument.
#[test]
fn postgres_schema_end_to_end() {
    multi_thread_rt().block_on(async {
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
        for ddl in [
            "CREATE SCHEMA sales",
            "CREATE TABLE orgs (id bigserial PRIMARY KEY, name text NOT NULL UNIQUE)",
            "CREATE TABLE sales.orders (org_id bigint NOT NULL, seq int NOT NULL, note text, \
             PRIMARY KEY (org_id, seq))",
            "CREATE TABLE sales.order_lines (org_id bigint NOT NULL, seq int NOT NULL, \
             sku text, qty int DEFAULT 1, \
             FOREIGN KEY (org_id, seq) REFERENCES sales.orders(org_id, seq))",
            "CREATE INDEX order_lines_sku_idx ON sales.order_lines(sku)",
            "CREATE VIEW v_orgs AS SELECT id, name FROM orgs",
            // A materialized view CAN carry indexes; the contract says a view
            // never does, so this one must not show up.
            "CREATE MATERIALIZED VIEW m_orgs AS SELECT id, name FROM orgs",
            "CREATE UNIQUE INDEX m_orgs_id_idx ON m_orgs(id)",
            // Partial: unique for the predicate rows only -> no unique claim.
            "CREATE UNIQUE INDEX orgs_partial_idx ON orgs(name) WHERE id > 0",
            // Display-name collision: public."sales.order_lines" renders like
            // sales.order_lines but is a different table.
            "CREATE TABLE public.\"sales.order_lines\" (x int)",
            // A foreign table reads like a table, so it must be listed like one.
            "CREATE EXTENSION file_fdw",
            "CREATE SERVER files FOREIGN DATA WRAPPER file_fdw",
            "CREATE FOREIGN TABLE ft_events (id int, note text) SERVER files \
             OPTIONS (filename '/dev/null', format 'csv')",
        ] {
            w.execute(ddl).await.unwrap();
        }
        w.close().await.unwrap();

        let tmp = tempfile::tempdir().unwrap();
        let cfg = write_pg_config(tmp.path(), port);

        let out = run(tmp.path(), &cfg, &["schema", "pg"]);
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        assert_no_password_leak(&out);
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["meta"]["table_count"], 7, "{v}");
        let tables = v["schema"]["tables"].as_array().unwrap();
        // public objects read as bare names, everything else is qualified —
        // and the list is ordered by that display name. The two colliding
        // `sales.order_lines` stay TWO objects (grouped by schema+name, not by
        // the display name).
        let names: Vec<&str> = tables.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(
            names,
            [
                "ft_events",
                "m_orgs",
                "orgs",
                "sales.order_lines",
                "sales.order_lines",
                "sales.orders",
                "v_orgs"
            ]
        );
        // Only the collision pair is addressed positionally (their names are
        // identical by construction): the quoted public one is the
        // single-column table, the real sales one keeps its four columns —
        // proof they did not merge.
        assert_eq!(tables[3]["columns"].as_array().unwrap().len(), 1);
        assert_eq!(tables[4]["columns"].as_array().unwrap().len(), 4);
        let table = |name: &str| {
            tables
                .iter()
                .find(|t| t["name"] == name)
                .unwrap_or_else(|| panic!("{name} missing: {v}"))
                .clone()
        };

        // A foreign table is reported as a table.
        assert_eq!(table("ft_events")["kind"], "table");
        assert_eq!(table("ft_events")["columns"][0]["name"], "id");

        // serial: pk, not null, the nextval default reported as the engine
        // words it; the single-column UNIQUE folds into a column flag, while
        // the PARTIAL unique index stays an index with no unique claim.
        assert_eq!(
            table("orgs"),
            serde_json::json!({
                "name": "orgs", "kind": "table",
                "columns": [
                    {"name": "id", "type": "bigint", "nullable": false, "pk": true,
                     "default": "nextval('orgs_id_seq'::regclass)"},
                    {"name": "name", "type": "text", "nullable": false, "unique": true}
                ],
                "indexes": [{"name": "orgs_partial_idx", "columns": ["name"]}]
            })
        );
        // Composite foreign key: ordered columns, schema-qualified parent.
        let order_lines = &tables[4];
        assert_eq!(
            order_lines["fks"],
            serde_json::json!([{
                "columns": ["org_id", "seq"],
                "ref_table": "sales.orders",
                "ref_columns": ["org_id", "seq"]
            }])
        );
        assert_eq!(
            order_lines["indexes"],
            serde_json::json!([{"name": "order_lines_sku_idx", "columns": ["sku"]}])
        );
        assert_eq!(order_lines["columns"][3]["default"], "1");
        // Composite primary key marks both members; its backing index is not
        // repeated under indexes.
        let orders = table("sales.orders");
        assert_eq!(orders["columns"][0]["pk"], true);
        assert_eq!(orders["columns"][1]["pk"], true);
        assert!(orders.get("indexes").is_none(), "{orders}");
        // A view: columns, no indexes/fks — and a MATERIALIZED view is a view
        // too, its own unique index included in "no indexes".
        assert_eq!(table("v_orgs")["kind"], "view");
        assert!(table("v_orgs")["columns"].is_array());
        let matview = table("m_orgs");
        assert_eq!(matview["kind"], "view");
        assert!(matview.get("indexes").is_none(), "{matview}");
        assert!(
            matview["columns"][0].get("unique").is_none(),
            "a matview index must not fold into a column flag: {matview}"
        );

        // A qualified [table] argument selects exactly one object...
        let out = run(tmp.path(), &cfg, &["schema", "pg", "sales.orders"]);
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["meta"]["table_count"], 1);
        assert_eq!(v["schema"]["tables"][0]["name"], "sales.orders");
        // ...and an unqualified one matches in every non-system schema.
        let out = run(tmp.path(), &cfg, &["schema", "pg", "orders"]);
        assert_eq!(out.status.code(), Some(0));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["schema"]["tables"][0]["name"], "sales.orders");
        // A dotted table NAME is reachable too: `[table]` splits on the FIRST
        // dot, so this picks the quoted public."sales.order_lines" (one column)
        // rather than the sales-schema table (four).
        let out = run(
            tmp.path(),
            &cfg,
            &["schema", "pg", "public.sales.order_lines"],
        );
        assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["meta"]["table_count"], 1);
        assert_eq!(v["schema"]["tables"][0]["name"], "sales.order_lines");
        assert_eq!(
            v["schema"]["tables"][0]["columns"],
            serde_json::json!([{"name": "x", "type": "integer", "nullable": true}])
        );
        // An unquoted identifier folds to lowercase in SQL, so `ORGS` must find
        // `orgs` here just as `SELECT * FROM ORGS` does.
        let out = run(tmp.path(), &cfg, &["schema", "pg", "ORGS"]);
        assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["schema"]["tables"][0]["name"], "orgs");

        // Unknown table (and a would-be injection) -> DB_ERROR, exit 7.
        for arg in ["nope", "sales.orders; DROP TABLE orgs", "orgs'--"] {
            let out = run(tmp.path(), &cfg, &["schema", "pg", arg]);
            assert_eq!(out.status.code(), Some(7), "{arg}: {}", stdout(&out));
            let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
            assert_eq!(v["error"]["code"], "DB_ERROR", "{arg}");
        }
        // System catalogs stay out of the answer even after all that.
        let out = run(tmp.path(), &cfg, &["schema", "pg"]);
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["meta"]["table_count"], 7);

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

/// SECURITY: pg_catalog is world-readable, so introspection must apply the
/// role's own privileges — otherwise `nyet schema` hands the agent every table
/// of every schema it cannot touch, DEFAULT expressions (literal data, where
/// secrets get parked) included.
#[test]
fn postgres_schema_respects_role_privileges() {
    multi_thread_rt().block_on(async {
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
        for ddl in [
            "CREATE TABLE visible (id int PRIMARY KEY, note text)",
            // (its pk must survive: the full-grant path is unfiltered)
            "CREATE SCHEMA secret",
            // The default is data: a token parked here must not leak.
            "CREATE TABLE secret.tokens (id int, api_key text DEFAULT 'sk-live-DEADBEEF')",
            // A table in a readable schema, but with no SELECT granted.
            "CREATE TABLE forbidden (id int, api_key text DEFAULT 'sk-live-CAFEBABE')",
            // Column-level grant: the role CAN read `note`, so the table must
            // show up — with `api_key` (and its default) left out. Its keys all
            // touch `api_key`, and pg_index/pg_constraint are NOT
            // privilege-filtered, so they are the leak to close.
            "CREATE TABLE vault (key text PRIMARY KEY)",
            "CREATE TABLE partly (id int, note text, \
             api_key text DEFAULT 'sk-live-C0FFEE' REFERENCES vault(key), \
             PRIMARY KEY (id, api_key))",
            "CREATE INDEX partly_mixed_idx ON partly (note, api_key)",
            "CREATE UNIQUE INDEX partly_secret_idx ON partly (api_key)",
            "CREATE INDEX partly_note_idx ON partly (note)",
            &format!("CREATE ROLE lowpriv LOGIN PASSWORD '{PW}'"),
            "GRANT SELECT ON visible TO lowpriv",
            "GRANT SELECT (id, note) ON partly TO lowpriv",
        ] {
            w.execute(sqlx::AssertSqlSafe(ddl.to_string()))
                .await
                .unwrap();
        }
        w.close().await.unwrap();

        let tmp = tempfile::tempdir().unwrap();
        let cfg = tmp.path().join("config.toml");
        std::fs::write(
            &cfg,
            format!(
                "[connections.pg]\nengine = \"postgres\"\n\
                 url = \"postgres://lowpriv@127.0.0.1:{port}/postgres\"\n\
                 password_env = \"{PW_ENV}\"\nallowed_dirs = [\"{}\"]\n",
                tmp.path().display()
            ),
        )
        .unwrap();

        let out = run(tmp.path(), &cfg, &["schema", "pg"]);
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        let body = stdout(&out);
        let v: serde_json::Value = serde_json::from_str(body.trim()).unwrap();
        // Exactly the granted tables: the table-wide grant and the
        // column-granted one (a role that can SELECT one column can read the
        // table, and `nyet query` would let it).
        assert_eq!(v["meta"]["table_count"], 2, "{v}");
        assert_eq!(v["schema"]["tables"][0]["name"], "partly");
        assert_eq!(v["schema"]["tables"][1]["name"], "visible");
        // ...but only the columns it may actually read, and NO key that touches
        // a column it may not: the composite pk (id, api_key) vanishes whole
        // rather than reading as a one-column key on `id`, both indexes over
        // api_key are gone, and so is the fk into `vault`. The index that only
        // uses granted columns stays.
        let partly = &v["schema"]["tables"][0];
        assert_eq!(
            partly["columns"],
            // `id` stays NOT NULL — that is a property of a column the role
            // MAY read; only the pk flag (which would misdescribe the key)
            // is dropped.
            serde_json::json!([
                {"name": "id", "type": "integer", "nullable": false},
                {"name": "note", "type": "text", "nullable": true}
            ]),
            "{partly}"
        );
        assert_eq!(
            partly["indexes"],
            serde_json::json!([{"name": "partly_note_idx", "columns": ["note"]}]),
            "{partly}"
        );
        assert!(partly.get("fks").is_none(), "{partly}");
        // The table-wide grant is untouched: its pk is still reported.
        assert_eq!(v["schema"]["tables"][1]["columns"][0]["pk"], true);
        // Nothing about what the role cannot read — names, columns, keys or
        // defaults.
        for leak in [
            "secret.tokens",
            "forbidden",
            "api_key",
            "vault",
            "partly_mixed_idx",
            "partly_secret_idx",
            "DEADBEEF",
            "CAFEBABE",
            "C0FFEE",
        ] {
            assert!(!body.contains(leak), "leaked {leak}: {body}");
        }
        // Naming one directly does not get around it either.
        for arg in ["secret.tokens", "forbidden"] {
            let out = run(tmp.path(), &cfg, &["schema", "pg", arg]);
            assert_eq!(out.status.code(), Some(7), "{arg}: {}", stdout(&out));
            assert!(!stdout(&out).contains("DEADBEEF"));
            assert!(!stdout(&out).contains("CAFEBABE"));
        }
        assert_no_password_leak(&out);

        container.rm().await.unwrap();
    });
}
