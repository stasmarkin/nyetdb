//! PostgreSQL end-to-end: drive the real binary against a throwaway Postgres
//! container (testcontainers + Docker/colima). Requires a reachable Docker
//! daemon; these tests fail (not skip) without one, so CI with a docker
//! service runs them. Pins exit codes and envelope structure (D7).

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

/// Config for the container, optionally with extra sections (a `[guardrail]`).
/// Each variant gets its own file name so several can coexist in one temp dir.
fn write_pg_config_with(dir: &Path, port: u16, extra: &str) -> std::path::PathBuf {
    let path = dir.join(format!("config{}.toml", extra.len()));
    std::fs::write(
        &path,
        format!(
            "[connections.pg]\nengine = \"postgres\"\n\
             url = \"postgres://postgres@127.0.0.1:{port}/postgres\"\n\
             password = {{ env = \"{PW_ENV}\" }}\nallowed_dirs = [\"{}\"]\n{extra}",
            dir.display()
        ),
    )
    .unwrap();
    path
}

fn write_pg_config(dir: &Path, port: u16) -> std::path::PathBuf {
    write_pg_config_with(dir, port, "")
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
        // exit 8. pg_sleep is denylisted, so use a huge generate_series scan —
        // which the auto-guardrail now refuses on sight (its plan costs 1.25e9,
        // way over the default limit), so this case turns the guardrail OFF to
        // keep testing the timeout path itself. That interaction is the point:
        // with the guardrail on, such a query never reaches the server at all.
        let unguarded = write_pg_config_with(
            tmp.path(),
            port,
            "[connections.pg.guardrail]\nmode = \"off\"\n",
        );
        let out = run(
            tmp.path(),
            &unguarded,
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

/// The auto-guardrail and `nyet explain` against a real planner: the default
/// (generous) threshold lets ordinary reads through and stops an obvious
/// monster, a configured threshold decides deterministically, and `off` really
/// is off. Nothing here relies on timing.
#[test]
fn postgres_guardrail_and_explain_end_to_end() {
    multi_thread_rt().block_on(async {
        let (container, port) = start_and_seed().await;
        let tmp = tempfile::tempdir().unwrap();
        let cfg = write_pg_config(tmp.path(), port);

        // 1) No [guardrail] section = the default (cost, 1e6): an ordinary read
        // is untouched, envelope byte-for-byte as before (no estimate field, no
        // warning) — the guardrail is invisible until it fires.
        let out = run(
            tmp.path(),
            &cfg,
            &["query", "pg", "SELECT id, email FROM users ORDER BY id"],
        );
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["meta"]["row_count"], 3);
        // The guardrail read a real estimate, so it stays silent: no
        // GUARDRAIL_SKIPPED, and a success envelope carries no `estimate`.
        assert!(!stdout(&out).contains("GUARDRAIL_SKIPPED"), "{v}");
        assert!(v.get("estimate").is_none(), "{v}");

        // 2) A real monster (10^12 rows out of a cross join) is refused by the
        // DEFAULT threshold — the whole point of shipping it on by default.
        let monster = "SELECT count(*) FROM generate_series(1, 1000000) a \
                       CROSS JOIN generate_series(1, 1000000) b";
        let out = run(tmp.path(), &cfg, &["query", "pg", monster]);
        assert_eq!(out.status.code(), Some(5), "{}", stdout(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["error"]["code"], "NYET");
        assert_eq!(v["error"]["reason"], "EXPENSIVE_QUERY");
        // The refusal teaches: the plan travels with it, and the way out names
        // the config key its owner can raise (there is no --force, on purpose).
        assert_eq!(v["estimate"]["mode"], "cost");
        assert_eq!(v["estimate"]["verdict"], "expensive");
        assert_eq!(v["estimate"]["threshold"], 1_000_000.0);
        assert!(v["estimate"]["cost"].as_f64().unwrap() > 1_000_000.0, "{v}");
        assert!(v["estimate"]["plan"][0]["Plan"].is_object(), "{v}");
        let hint = v["error"]["hint"].as_str().unwrap();
        assert!(
            hint.contains("[connections.pg.guardrail] max_cost"),
            "{hint}"
        );
        assert_no_password_leak(&out);

        // 3) A configured threshold decides — no reliance on planner magnitudes.
        let tiny = write_pg_config_with(
            tmp.path(),
            port,
            "[connections.pg.guardrail]\nmode = \"cost\"\nmax_cost = 1.0\n",
        );
        let out = run(tmp.path(), &tiny, &["query", "pg", "SELECT * FROM users"]);
        assert_eq!(out.status.code(), Some(5), "{}", stdout(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["error"]["reason"], "EXPENSIVE_QUERY");
        assert_eq!(v["estimate"]["threshold"], 1.0);
        // ...and rows mode judges rows instead: 3 planned rows > a limit of 1.
        let rows_mode = write_pg_config_with(
            tmp.path(),
            port,
            "[connections.pg.guardrail]\nmode = \"rows\"\nmax_rows = 1\n",
        );
        let out = run(
            tmp.path(),
            &rows_mode,
            &["query", "pg", "SELECT * FROM users"],
        );
        assert_eq!(out.status.code(), Some(5), "{}", stdout(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["estimate"]["mode"], "rows");
        assert_eq!(v["estimate"]["threshold"], 1);
        assert!(v["estimate"]["rows"].as_u64().unwrap() >= 3, "{v}");

        // 4) mode = "off" really is off: the same query that the 1.0 threshold
        // above refused now runs.
        let cfg_off = write_pg_config_with(
            tmp.path(),
            port,
            "[connections.pg.guardrail]\nmode = \"off\"\n",
        );
        let out = run(tmp.path(), &cfg_off, &["query", "pg", "SELECT * FROM users"]);
        assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));

        // 5) A metadata statement carries no plan, so the guardrail leaves it
        // alone — even under the 1.0 threshold that refuses everything else.
        let out = run(tmp.path(), &tiny, &["query", "pg", "SHOW search_path"]);
        assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
        let out = run(tmp.path(), &tiny, &["query", "pg", "EXPLAIN SELECT 1"]);
        assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));

        // 6) nyet explain: the plan plus an informational verdict, and nothing
        // executed either way (exit 0 even for the monster).
        let out = run(
            tmp.path(),
            &cfg,
            &["explain", "pg", "SELECT id FROM users WHERE id = 1"],
        );
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["estimate"]["mode"], "cost");
        assert_eq!(v["estimate"]["verdict"], "ok");
        assert!(v["estimate"]["cost"].as_f64().unwrap() < 1_000_000.0, "{v}");
        assert!(v["estimate"]["rows"].is_u64(), "{v}");
        assert!(
            v["estimate"]["plan"][0]["Plan"]["Node Type"].is_string(),
            "{v}"
        );
        assert_eq!(v["meta"]["connection"], "pg");
        assert_no_password_leak(&out);

        let out = run(tmp.path(), &cfg, &["explain", "pg", monster]);
        assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["estimate"]["verdict"], "expensive");
        // The table format renders the plan for human eyes on stdout.
        let out = run(
            tmp.path(),
            &cfg,
            &["explain", "pg", "SELECT * FROM users", "--format", "table"],
        );
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        assert!(
            stdout(&out).starts_with("verdict: ok (mode cost)"),
            "{}",
            stdout(&out)
        );
        assert!(stdout(&out).contains("Seq Scan"), "{}", stdout(&out));

        // 7) A RECURSIVE CTE: PostgreSQL does not estimate the iteration, so the
        // plan of an unbounded recursion costs ~3.35 — the guardrail must
        // refuse to JUDGE such a plan instead of blessing it. The query still
        // runs (bounded here so the test is fast) and says so.
        //
        // ...but that must NOT be an off switch: the same trivial CTE glued
        // onto the monster leaves the monster's own cost in the plan, so the
        // refusal stands (this exact trick disabled the guardrail before).
        let disguised = "WITH RECURSIVE z(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM z WHERE n < 2)              SELECT count(*) FROM generate_series(1, 1000000) a              CROSS JOIN generate_series(1, 1000000) b WHERE a = (SELECT max(n) FROM z)";
        let out = run(tmp.path(), &cfg, &["query", "pg", disguised]);
        assert_eq!(out.status.code(), Some(5), "{}", stdout(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["error"]["reason"], "EXPENSIVE_QUERY", "{v}");
        let recursive = "WITH RECURSIVE c(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM c                          WHERE n < 10) SELECT count(*) FROM c";
        let out = run(tmp.path(), &cfg, &["query", "pg", recursive]);
        assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["rows"][0]["count"], 10);
        let warnings = v["warnings"].as_array().unwrap();
        let skipped = warnings
            .iter()
            .find(|w| w["code"] == "GUARDRAIL_SKIPPED")
            .unwrap_or_else(|| panic!("no GUARDRAIL_SKIPPED: {v}"));
        // D10: the warning says what to do about it.
        assert!(
            skipped["message"].as_str().unwrap().contains("WHERE/LIMIT"),
            "{skipped}"
        );
        // ...and `nyet explain` reports no_estimate — NOT a confident "ok".
        let out = run(tmp.path(), &cfg, &["explain", "pg", recursive]);
        assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["estimate"]["verdict"], "no_estimate", "{v}");
        // The number is still shown — it is a LOWER bound, not a verdict, and
        // the missing `threshold` says nothing was compared.
        assert!(v["estimate"]["cost"].is_number(), "{v}");
        assert!(v["estimate"].get("threshold").is_none(), "{v}");
        assert!(
            v["warnings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|w| w["code"] == "GUARDRAIL_SKIPPED"),
            "{v}"
        );

        // 8) A query the server cannot plan is an ordinary DB_ERROR (exit 7)
        // with the REAL reason: the guardrail's EXPLAIN fails first and aborts
        // the transaction, so without the SAVEPOINT around it the query below
        // would report "current transaction is aborted" instead of the missing
        // relation — the fail-open path would be broken on Postgres entirely.
        let out = run(tmp.path(), &cfg, &["query", "pg", "SELECT * FROM nope_x"]);
        assert_eq!(out.status.code(), Some(7), "{}", stdout(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        let message = v["error"]["message"].as_str().unwrap();
        assert!(message.contains("nope_x"), "{message}");
        assert!(!message.contains("transaction is aborted"), "{message}");
        let out = run(tmp.path(), &cfg, &["explain", "pg", "SELECT * FROM nope_x"]);
        assert_eq!(out.status.code(), Some(7), "{}", stdout(&out));

        // 8b) PLANNING TIME IS AGENT-CONTROLLABLE: PostgreSQL folds IMMUTABLE
        // expressions while planning, so a chain of md5(repeat(...)) makes the
        // EXPLAIN itself take seconds (measured: 583ms for three 60MB terms).
        // If "no plan in time" fell open, that would be the cheapest guardrail
        // off switch there is — so exceeding the guardrail's budget REFUSES,
        // with the same EXPENSIVE_QUERY reason and no plan to show.
        // Sized for determinism, not for speed: 48 terms of ~130ms of planning
        // each (~6s) against a 5s budget (`--timeout 10` -> the 5s cap) and a
        // 10s query deadline. Both margins are wide, and the deciding timer is
        // a timer, not the work — with the budget and the client deadline set to
        // the same instant this case used to flake one run in three, and the
        // losing branch fell OPEN. NB: PostgreSQL does NOT interrupt plan-time
        // const-folding on `statement_timeout`, so here the client deadline is
        // the one that fires; the connection is dropped rather than tidied
        // (tidying would queue behind the very planning we gave up on).
        let padding: Vec<String> = (0..48)
            .map(|i| format!("md5(repeat('{i}', 40000000))"))
            .collect();
        let slow_to_plan = format!("SELECT {}", padding.join(" || "));
        let out = run(
            tmp.path(),
            &cfg,
            &["query", "pg", &slow_to_plan, "--timeout", "10"],
        );
        assert_eq!(out.status.code(), Some(5), "{}", stdout(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["error"]["code"], "NYET");
        assert_eq!(v["error"]["reason"], "EXPENSIVE_QUERY", "{v}");
        assert!(
            v["error"]["message"].as_str().unwrap().contains("budget"),
            "{v}"
        );
        assert!(v.get("estimate").is_none(), "no plan was obtained: {v}");
        // 8c) The same thing on a SHORT timeout, where the margins are thin:
        // with `--timeout 2` the guardrail's deadline is 1.8s and the query's is
        // 2s, so the refusal has to come out of a busy connection without any
        // polite cleanup — that cleanup used to queue behind the abandoned
        // planning and let the outer timer answer TIMEOUT instead.
        let out = run(
            tmp.path(),
            &cfg,
            &["query", "pg", &slow_to_plan, "--timeout", "2"],
        );
        assert_eq!(out.status.code(), Some(5), "{}", stdout(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["error"]["reason"], "EXPENSIVE_QUERY", "{v}");
        // `nyet explain` runs the SAME budget (it has no --timeout flag, so the
        // connection's timeout_secs decides), so it agrees with the query
        // instead of grinding for the full timeout and reporting a cheerful
        // "ok": no plan, an honest no_estimate, and a warning that says what
        // `nyet query` would do.
        let short = write_pg_config_with(tmp.path(), port, "timeout_secs = 2\n");
        let out = run(tmp.path(), &short, &["explain", "pg", &slow_to_plan]);
        assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["estimate"]["verdict"], "no_estimate", "{v}");
        assert_eq!(v["estimate"]["plan"], serde_json::json!([]), "{v}");
        let warned = v["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|w| w["code"] == "GUARDRAIL_SKIPPED")
            .unwrap_or_else(|| panic!("no GUARDRAIL_SKIPPED: {v}"));
        assert!(
            warned["message"].as_str().unwrap().contains("budget"),
            "{warned}"
        );

        // ...and with the guardrail off the same statement is just a query
        // again (bounded by the timeout, as before) — the refusal above is the
        // guardrail's doing, not a new blanket ban.
        let out = run(
            tmp.path(),
            &cfg_off,
            &["query", "pg", &slow_to_plan, "--timeout", "10"],
        );
        assert!(
            matches!(out.status.code(), Some(0 | 8)),
            "{:?}: {}",
            out.status.code(),
            stdout(&out)
        );

        // 9) The BRITISH spelling of ANALYZE executes the query just the same,
        // and it used to sail past the validator (verified: it ran a 2e7-row
        // aggregate). Refused, like every other EXPLAIN ANALYZE.
        for statement in [
            "EXPLAIN (ANALYSE) SELECT count(*) FROM users",
            "EXPLAIN (BUFFERS, ANALYSE) SELECT count(*) FROM users",
            "EXPLAIN (ANALYZE, FORMAT JSON) SELECT count(*) FROM users",
        ] {
            let out = run(tmp.path(), &cfg, &["query", "pg", statement]);
            assert_eq!(out.status.code(), Some(5), "{statement}: {}", stdout(&out));
            let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
            assert_eq!(v["error"]["reason"], "EXPLAIN_ANALYZE", "{statement}");
        }

        container.rm().await.unwrap();
    });
}

/// `nyet doctor` against a real PostgreSQL: the hybrid layer-3 check (metadata +
/// a write probe with layer 2 removed). A superuser fails read_only_role AND
/// not_superuser; a SELECT-only role passes both. The probe is proven to ROLL
/// BACK — no probe table survives and the data is intact — and the transport
/// check reports the guarantee (a require-mode url is `ok` even when the connect
/// then fails on the no-TLS container). Always exit 0.
#[test]
fn postgres_doctor_end_to_end() {
    multi_thread_rt().block_on(async {
        let (container, port) = start_and_seed().await;
        let tmp = tempfile::tempdir().unwrap();

        // A dedicated read-only role: SELECT only, no CREATE on schema public
        // (PostgreSQL 15+ no longer grants that to PUBLIC), so its probe write
        // is refused by the server.
        use sqlx::{ConnectOptions, Connection, Executor};
        let opts: sqlx::postgres::PgConnectOptions =
            format!("postgres://postgres@127.0.0.1:{port}/postgres")
                .parse()
                .unwrap();
        let mut w = opts.password(PW).connect().await.unwrap();
        for ddl in [
            format!(
                "CREATE ROLE nyet_ro LOGIN PASSWORD '{PW}' NOSUPERUSER NOCREATEDB NOCREATEROLE"
            ),
            "GRANT CONNECT ON DATABASE postgres TO nyet_ro".to_string(),
            "GRANT USAGE ON SCHEMA public TO nyet_ro".to_string(),
            "GRANT SELECT ON ALL TABLES IN SCHEMA public TO nyet_ro".to_string(),
            // A role that CAN write (INSERT) but lacks CREATE on the schema: its
            // probe CREATE is refused with 42501, which reads as read_only ok even
            // though it can INSERT — the documented DDL-vs-DML compromise.
            format!("CREATE ROLE writer LOGIN PASSWORD '{PW}' NOSUPERUSER NOCREATEDB NOCREATEROLE"),
            "GRANT CONNECT ON DATABASE postgres TO writer".to_string(),
            "GRANT USAGE ON SCHEMA public TO writer".to_string(),
            "GRANT INSERT ON users TO writer".to_string(),
        ] {
            w.execute(sqlx::AssertSqlSafe(ddl)).await.unwrap();
        }
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

        // 1) The superuser (postgres) role: it CAN write and IS a superuser, so
        // both layer-3 checks FAIL — but exit 0 (a diagnosis, not a refusal).
        let cfg = write_pg_config(tmp.path(), port);
        let out = run(tmp.path(), &cfg, &["doctor", "pg", "--format", "json"]);
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        assert_no_password_leak(&out);
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(by(&v, "connectivity")["status"], "ok");
        assert_eq!(by(&v, "read_only_role")["status"], "fail", "{v}");
        // The fail hint carries the actual SQL to create a read-only role (D10).
        assert!(by(&v, "read_only_role")["hint"]
            .as_str()
            .unwrap()
            .contains("CREATE ROLE nyet_ro"));
        assert_eq!(by(&v, "not_superuser")["status"], "fail", "{v}");
        // Default sslmode (prefer) gives no encryption guarantee -> warn.
        assert_eq!(by(&v, "transport_encrypted")["status"], "warn", "{v}");

        // 2) The probe ROLLED BACK: no probe table remains and the data is
        // untouched — the write never committed.
        let opts: sqlx::postgres::PgConnectOptions =
            format!("postgres://postgres@127.0.0.1:{port}/postgres")
                .parse()
                .unwrap();
        let mut c = opts.password(PW).connect().await.unwrap();
        let probes: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_tables WHERE tablename LIKE 'nyet_doctor_probe_%'",
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

        // 3) The read-only role: the server refuses its probe write, so
        // read_only_role is OK, and it is not a superuser.
        let ro = tmp.path().join("ro.toml");
        std::fs::write(
            &ro,
            format!(
                "[connections.pg]\nengine = \"postgres\"\n\
                 url = \"postgres://nyet_ro@127.0.0.1:{port}/postgres\"\n\
                 password = {{ env = \"{PW_ENV}\" }}\nallowed_dirs = [\"{}\"]\n",
                tmp.path().display()
            ),
        )
        .unwrap();
        let out = run(tmp.path(), &ro, &["doctor", "pg", "--format", "json"]);
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(by(&v, "read_only_role")["status"], "ok", "{v}");
        assert!(by(&v, "read_only_role").get("hint").is_none(), "{v}");
        assert_eq!(by(&v, "not_superuser")["status"], "ok", "{v}");

        // 3b) DOCUMENTED FALSE OK (the DDL-vs-DML compromise, pinned): the
        // `writer` role can INSERT but lacks CREATE, so its probe CREATE is
        // refused with 42501 and reads as read_only ok even though it can write.
        // The recommended layer-3 role is SELECT-only, so the compromise is
        // acceptable — but pinned here so a change is a conscious one.
        let writer = tmp.path().join("writer.toml");
        std::fs::write(
            &writer,
            format!(
                "[connections.pg]\nengine = \"postgres\"\n\
                 url = \"postgres://writer@127.0.0.1:{port}/postgres\"\n\
                 password = {{ env = \"{PW_ENV}\" }}\nallowed_dirs = [\"{}\"]\n",
                tmp.path().display()
            ),
        )
        .unwrap();
        let out = run(tmp.path(), &writer, &["doctor", "pg", "--format", "json"]);
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(by(&v, "read_only_role")["status"], "ok", "{v}");

        // 4) Transport reports the GUARANTEE, statically: a require-mode url is
        // `ok` for transport even though the connect then FAILS against the
        // no-TLS container (connectivity fail) — both are exit 0.
        let tls = tmp.path().join("tls.toml");
        std::fs::write(
            &tls,
            format!(
                "[connections.pg]\nengine = \"postgres\"\n\
                 url = \"postgres://postgres@127.0.0.1:{port}/postgres?sslmode=require\"\n\
                 password = {{ env = \"{PW_ENV}\" }}\nallowed_dirs = [\"{}\"]\n",
                tmp.path().display()
            ),
        )
        .unwrap();
        let out = run(tmp.path(), &tls, &["doctor", "pg", "--format", "json"]);
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(by(&v, "transport_encrypted")["status"], "ok", "{v}");
        assert_eq!(by(&v, "connectivity")["status"], "fail", "{v}");

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
                 password = {{ env = \"{PW_ENV}\" }}\nallowed_dirs = [\"{}\"]\n",
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

/// PostgreSQL's `*_to_xml` family runs a SQL string the parser never sees and
/// dumps whole relations without naming a column. Denied for EVERY connection,
/// PII policy or not: it re-enables every function the validator refuses.
#[test]
fn postgres_xml_export_functions_are_denied() {
    multi_thread_rt().block_on(async {
        let (container, port) = start_and_seed().await;
        let tmp = tempfile::tempdir().unwrap();
        let cfg = write_pg_config(tmp.path(), port);
        for sql in [
            "SELECT query_to_xml('select email from users', true, false, '')::text",
            "SELECT table_to_xml('users'::regclass, true, false, '')::text",
            "SELECT cast(schema_to_xml('public', true, false, '') as text)",
            "SELECT xpath('//email/text()', query_to_xml('select email from users', \
             true, false, ''))::text",
            // the wider defect: the family re-enabled the whole function denylist
            "SELECT query_to_xml('select pg_sleep(3)', true, false, '')::text",
        ] {
            let out = run(tmp.path(), &cfg, &["query", "pg", sql]);
            assert_eq!(out.status.code(), Some(5), "{sql}: {}", stdout(&out));
            let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
            assert_eq!(v["error"]["reason"], "DENIED_FUNCTION", "{sql}");
            assert!(!stdout(&out).contains("a@b.c"), "leaked: {}", stdout(&out));
        }
        // Neighbouring functions are untouched (the enumeration is exact).
        for sql in [
            "SELECT xmlcomment('ok')::text AS v",
            "SELECT * FROM generate_series(1, 3) AS g",
            "SELECT unnest(ARRAY[1, 2]) AS n",
        ] {
            let out = run(tmp.path(), &cfg, &["query", "pg", sql]);
            assert_eq!(out.status.code(), Some(0), "{sql}: {}", stdout(&out));
        }
        container.rm().await.unwrap();
    });
}

/// Advisory locks against a live server. What this test MEASURES is one thing the
/// corpus cannot show: the refusal reaches the agent as `DENIED_FUNCTION` + exit 5
/// on a real connection, in every spelling.
///
/// The closing `pg_locks` assertion is a **pin for later, not today's proof**:
/// nyet runs one process per invocation, and a session advisory lock dies with the
/// backend, so the count would read 0 even with the denylist removed (measured —
/// with `allow_functions` on the family, `pg_locks` shows the lock INSIDE the query
/// and 0 once the process exits). What makes the family dangerous is that
/// `ROLLBACK` does not release a session lock (also measured: taken inside the
/// read-only transaction, it is still held after the abort) — so the day
/// connections are reused, that assertion starts failing if layer 1 ever stops
/// refusing. Kept for exactly that day.
#[test]
fn postgres_advisory_locks_are_denied() {
    multi_thread_rt().block_on(async {
        let (container, port) = start_and_seed().await;
        let tmp = tempfile::tempdir().unwrap();
        let cfg = write_pg_config(tmp.path(), port);
        for sql in [
            "SELECT pg_advisory_lock(42)",
            "SELECT pg_try_advisory_lock(42)",
            "SELECT pg_advisory_lock_shared(1, 2)",
            "SELECT pg_advisory_unlock_all()",
            // transactional variants: released at ROLLBACK, denied all the same
            "SELECT pg_advisory_xact_lock(42)",
            "SELECT pg_try_advisory_xact_lock(42)",
            // and through the table-function / qualified spellings
            "SELECT * FROM pg_advisory_lock(42)",
            "SELECT pg_catalog.pg_try_advisory_lock(42)",
        ] {
            let out = run(tmp.path(), &cfg, &["query", "pg", sql]);
            assert_eq!(out.status.code(), Some(5), "{sql}: {}", stdout(&out));
            let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
            assert_eq!(v["error"]["reason"], "DENIED_FUNCTION", "{sql}");
        }
        // Nothing was taken: not a single advisory lock on the whole server.
        let out = run(
            tmp.path(),
            &cfg,
            &[
                "query",
                "pg",
                "SELECT count(*) AS n FROM pg_locks WHERE locktype = 'advisory'",
            ],
        );
        assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["rows"][0]["n"], 0, "advisory lock left behind: {v}");
        container.rm().await.unwrap();
    });
}

/// The PII policy against a live PostgreSQL (step PII-1): net A by name, net B
/// by the driver's column provenance, the withheld database error, and the
/// honestly documented view limitation — all measured, not assumed.
#[test]
fn postgres_pii_policy_end_to_end() {
    multi_thread_rt().block_on(async {
        let (container, port) = start_and_seed().await;
        // A distinctive cell value: any appearance in either stream is a leak.
        const VALUE: &str = "alice@example.com";
        {
            use sqlx::{ConnectOptions, Connection, Executor};
            let opts: sqlx::postgres::PgConnectOptions =
                format!("postgres://postgres@127.0.0.1:{port}/postgres")
                    .parse()
                    .unwrap();
            let mut w = opts.password(PW).connect().await.unwrap();
            for sql in [
                format!("INSERT INTO users VALUES (9, '{VALUE}')"),
                "CREATE TABLE orders (id int primary key, uid int, amount int)".to_string(),
                "INSERT INTO orders VALUES (1, 9, 42)".to_string(),
                "CREATE TABLE dict (id int, email text, note text)".to_string(),
                format!("INSERT INTO dict VALUES (9, '{VALUE}', 'x')"),
                "CREATE VIEW v_users AS SELECT id, email AS contact FROM users".to_string(),
            ] {
                w.execute(sqlx::AssertSqlSafe(sql)).await.unwrap();
            }
            w.close().await.unwrap();
        }
        let tmp = tempfile::tempdir().unwrap();
        let cfg = write_pg_config_with(
            tmp.path(),
            port,
            "[connections.pg.pii]\ncolumns = [\"users.email\"]\n",
        );
        let no_leak = |out: &Output, sql: &str| {
            assert!(!stdout(out).contains(VALUE), "{sql}: leaked to stdout");
            assert!(!stderr(out).contains(VALUE), "{sql}: leaked to stderr");
        };

        // Net A: the protected column by name, a whole-row projection, the
        // WHERE-oracle, and the value-sampling catalog.
        for sql in [
            "SELECT email FROM users",
            "SELECT u.email FROM users u",
            "SELECT * FROM users",
            "SELECT u FROM users u",
            "SELECT count(*) FROM users WHERE email LIKE 'a%'",
            "SELECT * FROM pg_stats",
            // finding 2: sqlparser reads `ONLY` as the table and `users` as its
            // alias — the server, however, runs the real query (verified: it
            // returns the protected value).
            "SELECT email FROM ONLY users",
            "SELECT * FROM ONLY users",
            // finding 5: f(t.*) expands the whole row inside a call. Verified
            // live: json_agg(u.*) returns {"id":..,"email":"alice@example.com"}.
            "SELECT json_agg(u.*)::text FROM users u",
            "SELECT concat(u.*) FROM users u",
            // finding 4: an alias column list renames columns positionally.
            "SELECT c FROM users AS u (a, b, c)",
            // finding 3: USING / NATURAL name the join column outside any Expr.
            "SELECT count(*) FROM users JOIN dict USING (email)",
            "SELECT count(*) FROM users NATURAL JOIN dict",
            // round 2, finding A: `TABLE t` keeps its name as a plain String
            // inside SetExpr — it used to switch net A off completely and
            // returned every column of users (verified live).
            "SELECT NULL AS a, NULL AS b, NULL AS c UNION ALL TABLE users",
            "SELECT NULL AS a UNION ALL TABLE pg_stats",
            // round 2, finding B: a parenthesised join hides its constraint.
            "SELECT count(*) FROM (users JOIN dict USING (email))",
            "SELECT count(*) FROM (users NATURAL JOIN dict)",
            "SELECT count(*) FROM orders o JOIN (users JOIN dict USING (email)) x ON true",
            // round 2, finding C: a function in TABLE-SOURCE position.
            "SELECT 1 FROM users u, LATERAL json_agg(u.*)",
            // round 3, finding B: `FROM ONLY (t)` — sqlparser reads it as a
            // TABLE FUNCTION, so the scan skipped it and net A went off
            // entirely. Verified live: each of these returned the value.
            "SELECT email || '' FROM ONLY (users)",
            "SELECT substr(email, 1, 5) AS x FROM ONLY (users)",
            "SELECT (SELECT email FROM ONLY (users) LIMIT 1) AS x",
            "SELECT count(*) FROM ONLY (users) WHERE email LIKE 'a%'",
            "SELECT count(*) FROM ONLY (users) JOIN dict USING (email)",
            "SELECT count(*) FROM ONLY (users) NATURAL JOIN dict",
            "SELECT * FROM ONLY (users)",
            "SELECT most_common_vals::text FROM ONLY (pg_stats) WHERE tablename = 'users'",
            "SELECT email FROM ONLY (public.users)",
            "SELECT 1 FROM (SELECT 1) z, ONLY (users)",
            // round 3, finding C: a wildcard over a parenthesised join must see
            // that join's own sources.
            "SELECT * FROM (users JOIN dict ON true)",
            "SELECT u.* FROM (users u JOIN dict ON true)",
            // round 4, finding 1: a correlated sub-SELECT has an empty FROM, so
            // a LOCAL wildcard scope saw nothing while `u.*` copied every
            // protected column outwards. The count form cleared BOTH nets.
            "SELECT count(*) FROM users u, LATERAL (SELECT u.*) s WHERE s.email LIKE 'a%'",
            "SELECT s.email FROM users u, LATERAL (SELECT u.*) s",
            "SELECT count(*) FROM users u CROSS JOIN LATERAL (SELECT u.*) AS s(a, b, c, d) \
             WHERE s.b LIKE 'a%'",
        ] {
            let out = run(tmp.path(), &cfg, &["query", "pg", sql]);
            assert_eq!(out.status.code(), Some(5), "{sql}: {}", stdout(&out));
            let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
            assert_eq!(v["error"]["reason"], "PII_COLUMN", "{sql}");
            no_leak(&out, sql);
            assert_no_password_leak(&out);
        }

        // Net B must not fire on a legitimate read: this proves the extra
        // DESCRIBE really resolves origins on the FETCH path (without it every
        // Postgres column comes back Unknown and this would be PII_UNPROVABLE).
        for sql in [
            "SELECT id FROM users ORDER BY id",
            "SELECT count(*) AS n FROM users",
            "SELECT * FROM orders",
            // An EMPTY result takes the prepared-statement column path: its
            // origins must be resolved there too, or this would be a refusal.
            "SELECT id, amount FROM orders WHERE 1 = 0",
            // Metadata statements have no table columns at all.
            "SHOW server_version",
            "SELECT 1 AS one",
            // finding 9: the wildcard's own source carries no rules.
            "SELECT * FROM orders WHERE uid IN (SELECT id FROM users)",
            "SELECT o.* FROM orders o JOIN users u ON u.id = o.uid",
            "SELECT count(*) FROM users JOIN dict USING (id)",
            // round 2, findings D/E/F.
            "SELECT * FROM (SELECT id FROM users) t",
            "SELECT o.uid FROM orders o JOIN users u ON u.id = o.uid",
            "SELECT amount FROM orders AS users",
            // round 3, finding D: a derived table's alias is a provable source.
            "SELECT s.uid FROM users u JOIN (SELECT id, uid FROM orders) s ON s.id = u.id",
            "SELECT * FROM generate_series(1, 3) AS g",
        ] {
            let out = run(tmp.path(), &cfg, &["query", "pg", sql]);
            // NET B LIVENESS: this is the assertion that goes red if sqlx ever
            // stops resolving column origins on this path. Blinded origins come
            // back as ColumnOrigin::Unknown, which net B refuses as
            // PII_UNPROVABLE (exit 5) — so a silent regression cannot pass here.
            assert_eq!(out.status.code(), Some(0), "{sql}: {}", stdout(&out));
            let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
            assert_eq!(v["ok"], true, "{sql}");
            no_leak(&out, sql);
        }

        // Leak guard: the query never NAMES a protected column (it goes through
        // the view), so it runs — and PostgreSQL answers `invalid input syntax
        // for type integer: "alice@example.com"`. The PII policy withholds that
        // message wholesale; the value must not reach either stream.
        let sql = "SELECT contact::int FROM v_users";
        let out = run(tmp.path(), &cfg, &["query", "pg", sql]);
        assert_eq!(out.status.code(), Some(7), "{}", stdout(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["error"]["code"], "DB_ERROR");
        assert!(
            v["error"]["message"].as_str().unwrap().contains("withheld"),
            "{v}"
        );
        no_leak(&out, sql);

        // The honest limitation (README/DEV): PostgreSQL reports a VIEW column's
        // origin as the view itself, so a rule on the base table does not cover
        // the view — the config owner must list it.
        let out = run(
            tmp.path(),
            &cfg,
            &["query", "pg", "SELECT contact FROM v_users"],
        );
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        assert!(
            stdout(&out).contains(VALUE),
            "the documented view limitation changed: {}",
            stdout(&out)
        );
        // ...and listing the view closes it.
        let cfg_view = write_pg_config_with(
            tmp.path(),
            port,
            "[connections.pg.pii]\ncolumns = [\"users.email\", \"v_users.contact\"]\n",
        );
        let out = run(
            tmp.path(),
            &cfg_view,
            &["query", "pg", "SELECT contact FROM v_users"],
        );
        assert_eq!(out.status.code(), Some(5), "{}", stdout(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["error"]["reason"], "PII_COLUMN");
        no_leak(&out, "SELECT contact FROM v_users (view listed)");

        // A connection WITHOUT a [pii] section is untouched, error text included.
        let plain = write_pg_config(tmp.path(), port);
        let out = run(
            tmp.path(),
            &plain,
            &["query", "pg", "SELECT email FROM users ORDER BY id"],
        );
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        assert!(stdout(&out).contains(VALUE), "{}", stdout(&out));
        let out = run(
            tmp.path(),
            &plain,
            &["query", "pg", "SELECT nosuchcol FROM orders"],
        );
        assert_eq!(out.status.code(), Some(7));
        assert!(stdout(&out).contains("nosuchcol"), "{}", stdout(&out));

        container.rm().await.unwrap();
    });
}

/// `mode = "mask"` on a LIVE driver: the redaction rides on the provenance the
/// server reported, so this is the only place the promise "net A relaxes what
/// net B can prove" is actually verified against PostgreSQL. Plus the leak
/// guard (stdout / stderr / audit log) and the `pii_columns` doctor check
/// against two real roles — one that may read the column and one that may not.
#[test]
fn postgres_pii_mask_end_to_end() {
    multi_thread_rt().block_on(async {
        let (container, port) = start_and_seed().await;
        const VALUE: &str = "alice@example.com";
        {
            use sqlx::{ConnectOptions, Connection, Executor};
            let opts: sqlx::postgres::PgConnectOptions =
                format!("postgres://postgres@127.0.0.1:{port}/postgres")
                    .parse()
                    .unwrap();
            let mut w = opts.password(PW).connect().await.unwrap();
            for sql in [
                format!("INSERT INTO users VALUES (9, '{VALUE}')"),
                "CREATE TABLE dict (id int, email text)".to_string(),
                "CREATE VIEW v_users AS SELECT id, email AS contact FROM users".to_string(),
                "INSERT INTO dict VALUES (1, 'd@e.f')".to_string(),
                // A second renaming view: the shape that proved a wildcard beside
                // a masked column shifts every index to its right.
                "CREATE VIEW v_dict AS SELECT id, email AS work_mail FROM dict".to_string(),
                // A role with SELECT on everything -> the policy is the ONLY
                // boundary (doctor must say so), and one whose column grant
                // makes the database enforce it too.
                format!("CREATE ROLE pii_all LOGIN PASSWORD '{PW}'"),
                "GRANT SELECT ON users TO pii_all".to_string(),
                // The view over the protected column, readable by this role —
                // the gap the pii_views check exists to name (W7).
                "GRANT SELECT ON v_users TO pii_all".to_string(),
                format!("CREATE ROLE pii_none LOGIN PASSWORD '{PW}'"),
                "GRANT SELECT (id) ON users TO pii_none".to_string(),
            ] {
                w.execute(sqlx::AssertSqlSafe(sql)).await.unwrap();
            }
            w.close().await.unwrap();
        }
        let tmp = tempfile::tempdir().unwrap();
        let cfg = write_pg_config_with(
            tmp.path(),
            port,
            "[connections.pg.pii]\ncolumns = [\"users.email\"]\nmode = \"mask\"\n\
             [audit]\nlog_responses = true\n",
        );
        let no_leak = |out: &Output, sql: &str| {
            assert!(!stdout(out).contains(VALUE), "{sql}: leaked to stdout");
            assert!(!stderr(out).contains(VALUE), "{sql}: leaked to stderr");
        };

        // The plain projection runs, and every cell of the protected column is
        // gone — the NULL row included (seeded as id 3), so the mask does not
        // answer "is this value set?".
        let sql = "SELECT id, email FROM users";
        let out = run(tmp.path(), &cfg, &["query", "pg", sql]);
        assert_eq!(out.status.code(), Some(0), "{sql}: {}", stdout(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        let rows = v["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 4, "{v}");
        for row in rows {
            assert_eq!(row["email"], "[REDACTED]", "{v}");
        }
        assert_eq!(v["warnings"][0]["code"], "PII_MASKED", "{v}");
        assert!(
            v["warnings"][0]["message"]
                .as_str()
                .unwrap()
                .contains("'email'"),
            "{v}"
        );
        no_leak(&out, sql);
        assert_no_password_leak(&out);

        // LEAK GUARD: what the human's forensic log holds is exactly what the
        // agent saw — masked. (The raw SQL stays, by design.)
        let audit = tmp.path().join(".local/share/nyet/audit.jsonl");
        let text = std::fs::read_to_string(&audit).expect("audit file must exist");
        assert!(!text.contains(VALUE), "the audit log leaked the value");
        assert!(text.contains("[REDACTED]"), "{text}");

        // Everything that could read the value back out keeps the deny-mode
        // refusal — including every hole closed in PII-1.
        for sql in [
            "SELECT count(*) FROM users WHERE email LIKE 'a%'",
            "SELECT email FROM users ORDER BY 1",
            "SELECT DISTINCT email FROM users",
            "SELECT email AS x FROM users",
            "SELECT * FROM users",
            "SELECT u FROM users u",
            "SELECT json_agg(u.*)::text FROM users u",
            "SELECT email FROM ONLY (users)",
            "SELECT NULL AS a, NULL AS b UNION ALL TABLE users",
            "SELECT count(*) FROM users JOIN dict USING (email)",
            "SELECT count(*) FROM users u, LATERAL (SELECT u.*) s WHERE s.email LIKE 'a%'",
            "SELECT most_common_vals::text FROM pg_stats WHERE tablename = 'users'",
        ] {
            let out = run(tmp.path(), &cfg, &["query", "pg", sql]);
            assert_eq!(out.status.code(), Some(5), "{sql}: {}", stdout(&out));
            let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
            assert_eq!(v["error"]["reason"], "PII_COLUMN", "{sql}");
            no_leak(&out, sql);
        }

        // The exemption is a PROMISE net B must keep. PostgreSQL reports a view
        // column's origin as the VIEW, so the README's "list the view" recipe
        // masks correctly here...
        let cfg_view = write_pg_config_with(
            tmp.path(),
            port,
            "[connections.pg.pii]\ncolumns = [\"v_users.contact\"]\nmode = \"mask\"\n",
        );
        let out = run(
            tmp.path(),
            &cfg_view,
            &["query", "pg", "SELECT contact FROM v_users"],
        );
        assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["rows"][0]["contact"], "[REDACTED]", "{v}");
        no_leak(&out, "SELECT contact FROM v_users");
        // ...and where the promise CANNOT be kept — a computed value carries no
        // provenance — the answer is a refusal, never the value.
        let sql = "WITH users AS (SELECT 'secret'::text AS email) SELECT email FROM users";
        let out = run(tmp.path(), &cfg, &["query", "pg", sql]);
        assert_eq!(out.status.code(), Some(5), "{sql}: {}", stdout(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["error"]["reason"], "PII_UNPROVABLE", "{v}");
        assert!(!stdout(&out).contains("secret"), "{}", stdout(&out));

        // A wildcard beside a column to be masked is refused on the live driver
        // too: `*` expands into N columns, so the promise net B checks by index
        // would be kept by the wrong one (measured raw leak on SQLite, round 2).
        let cfg_two = write_pg_config_with(
            tmp.path(),
            port,
            "[connections.pg.pii]\ncolumns = [\"users.email\", \"v_dict.work_mail\"]\n\
             mode = \"mask\"\n",
        );
        for sql in [
            "SELECT c.*, d.work_mail FROM dict c, v_dict d",
            "SELECT d.work_mail, c.* FROM dict c, v_dict d",
        ] {
            let out = run(tmp.path(), &cfg_two, &["query", "pg", sql]);
            assert_eq!(out.status.code(), Some(5), "{sql}: {}", stdout(&out));
            let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
            assert_eq!(v["error"]["reason"], "PII_COLUMN", "{sql}");
            no_leak(&out, sql);
        }
        // Naming the columns is the way through, and the protected one is masked.
        let out = run(
            tmp.path(),
            &cfg_two,
            &["query", "pg", "SELECT id, work_mail FROM v_dict"],
        );
        assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["rows"][0]["work_mail"], "[REDACTED]", "{v}");

        // doctor, against the two real roles.
        let doctor_pii = |user: &str| {
            let cfg = tmp.path().join(format!("doctor-{user}.toml"));
            std::fs::write(
                &cfg,
                format!(
                    "[connections.pg]\nengine = \"postgres\"\n\
                     url = \"postgres://{user}@127.0.0.1:{port}/postgres\"\n\
                     password = {{ env = \"{PW_ENV}\" }}\nallowed_dirs = [\"{}\"]\n\
                     [connections.pg.pii]\ncolumns = [\"users.email\"]\nmode = \"mask\"\n",
                    tmp.path().display()
                ),
            )
            .unwrap();
            let out = run(tmp.path(), &cfg, &["doctor", "pg", "--format", "json"]);
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
        // The role CAN read it -> honest warn: nyet is the only boundary.
        let check = doctor_pii("pii_all");
        assert_eq!(check["status"], "warn", "{check}");
        assert!(
            check["message"].as_str().unwrap().contains("users.email"),
            "{check}"
        );
        assert!(
            check["hint"].as_str().unwrap().contains("REVOKE SELECT"),
            "{check}"
        );
        // A column-level grant makes the database enforce the same boundary.
        let check = doctor_pii("pii_none");
        assert_eq!(check["status"], "ok", "{check}");
        assert!(
            check["message"].as_str().unwrap().contains("cannot read"),
            "{check}"
        );

        // W7: a [pii] rule is keyed to the table it names, so a VIEW over the
        // protected column is a way around it — and one the human is unlikely
        // to think of. doctor names such views instead of letting them find out
        // the hard way. The check walks pg_depend rather than
        // information_schema.view_column_usage, which only reports tables owned
        // by an enabled role and would hand the recommended read-only role a
        // false all-clear.
        let doctor_views = |user: &str| {
            let cfg = tmp.path().join(format!("views-{user}.toml"));
            std::fs::write(
                &cfg,
                format!(
                    "[connections.pg]\nengine = \"postgres\"\n\
                     url = \"postgres://{user}@127.0.0.1:{port}/postgres\"\n\
                     password = {{ env = \"{PW_ENV}\" }}\nallowed_dirs = [\"{}\"]\n\
                     [connections.pg.pii]\ncolumns = [\"users.email\"]\n",
                    tmp.path().display()
                ),
            )
            .unwrap();
            let out = run(tmp.path(), &cfg, &["doctor", "pg", "--format", "json"]);
            assert_eq!(out.status.code(), Some(0), "{user}: {}", stderr(&out));
            let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
            v["checks"]
                .as_array()
                .unwrap()
                .iter()
                .find(|c| c["name"] == "pii_views")
                .unwrap_or_else(|| panic!("{user}: no pii_views check: {v}"))
                .clone()
        };
        // v_users selects the protected column and pii_all may read it -> named.
        let check = doctor_views("pii_all");
        assert_eq!(check["status"], "warn", "{check}");
        assert!(
            check["message"].as_str().unwrap().contains("v_users"),
            "{check}"
        );
        // pii_none has no SELECT on the view, so there is nothing to warn about:
        // the check reports what THIS role can actually reach, not every view.
        let check = doctor_views("pii_none");
        assert_eq!(check["status"], "ok", "{check}");

        container.rm().await.unwrap();
    });
}

/// `nyet sample` on a real PostgreSQL: the qualified name, the PII policy, and
/// the one path only a server engine has — the guardrail refusing the random
/// draw, which turns into the cheap answer plus `SAMPLE_FALLBACK`.
#[test]
fn postgres_sample_end_to_end() {
    multi_thread_rt().block_on(async {
        let (container, port) = start_and_seed().await;
        {
            use sqlx::{ConnectOptions, Connection, Executor};
            let opts: sqlx::postgres::PgConnectOptions =
                format!("postgres://postgres@127.0.0.1:{port}/postgres")
                    .parse()
                    .unwrap();
            let mut w = opts.password(PW).connect().await.unwrap();
            for sql in [
                "CREATE SCHEMA sales",
                "CREATE TABLE sales.orders (id int primary key, total int)",
                "INSERT INTO sales.orders VALUES (1, 10), (2, 20)",
                // Big enough that sorting it (a random draw) plans far above a
                // plain LIMIT, so the fallback below is decided by the planner's
                // arithmetic and not by a lucky magnitude.
                "CREATE TABLE big AS SELECT g AS n, 'row' || g AS label \
                 FROM generate_series(1, 20000) g",
                "ANALYZE big",
            ] {
                w.execute(sql).await.unwrap();
            }
            w.close().await.unwrap();
        }
        let tmp = tempfile::tempdir().unwrap();
        let cfg = write_pg_config(tmp.path(), port);

        // 1) The ordinary answer: the query envelope, every column of the table.
        let out = run(tmp.path(), &cfg, &["sample", "pg", "users"]);
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        assert_no_password_leak(&out);
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["meta"]["row_count"], 3);
        assert_eq!(v["meta"]["truncated"], false);
        assert!(v["rows"][0]["id"].is_number(), "{v}");
        assert!(v["rows"][0].get("email").is_some(), "{v}");

        // 2) `schema.table` outside the search_path — the same argument shape
        //    `nyet schema` takes, split on the first dot.
        let out = run(tmp.path(), &cfg, &["sample", "pg", "sales.orders"]);
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["meta"]["row_count"], 2);
        // Unqualified, that same table is not on the search_path: a database
        // error, with the hint pointing at the name the agent can fix.
        let out = run(tmp.path(), &cfg, &["sample", "pg", "orders"]);
        assert_eq!(out.status.code(), Some(7), "{}", stdout(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["error"]["code"], "DB_ERROR");
        assert!(
            v["error"]["hint"]
                .as_str()
                .unwrap()
                .contains("nyet schema pg"),
            "{v}"
        );

        // 3) The guardrail refuses the random draw (sorting 20000 rows), so
        //    nyet asks the cheap question instead and SAYS SO. A plain
        //    `LIMIT 11` plans far under this threshold; the sort does not.
        let guarded = write_pg_config_with(
            tmp.path(),
            port,
            "[connections.pg.guardrail]\nmode = \"cost\"\nmax_cost = 50.0\n",
        );
        let out = run(tmp.path(), &guarded, &["sample", "pg", "big"]);
        assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["meta"]["row_count"], 10);
        let warnings = v["warnings"].as_array().unwrap();
        let fallback = warnings
            .iter()
            .find(|w| w["code"] == "SAMPLE_FALLBACK")
            .unwrap_or_else(|| panic!("no SAMPLE_FALLBACK: {v}"));
        // It must say what the rows are NOT, and how to insist on a real draw —
        // as a line that survives being pasted into a shell, quotes and all.
        let message = fallback["message"].as_str().unwrap();
        assert!(
            message.contains("nyet query pg 'SELECT * FROM \"big\" ORDER BY random() LIMIT 10'"),
            "{message}"
        );
        // The refusal is gone: the answer is a success, not a NYET.
        assert_eq!(v["ok"], true);
        // ...and the guardrail still refuses the draw when it is asked for
        // deliberately, which is what the warning promises.
        let out = run(
            tmp.path(),
            &guarded,
            &[
                "query",
                "pg",
                "SELECT * FROM \"big\" ORDER BY random() LIMIT 10",
            ],
        );
        assert_eq!(out.status.code(), Some(5), "{}", stdout(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["error"]["reason"], "EXPENSIVE_QUERY");

        // 4) A threshold under even the cheap statement: the fallback is
        //    refused too, and that refusal IS the answer — there is no third try.
        let strict = write_pg_config_with(
            tmp.path(),
            port,
            "[connections.pg.guardrail]\nmode = \"cost\"\nmax_cost = 0.001\n",
        );
        let out = run(tmp.path(), &strict, &["sample", "pg", "big"]);
        assert_eq!(out.status.code(), Some(5), "{}", stdout(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["error"]["code"], "NYET");
        assert_eq!(v["error"]["reason"], "EXPENSIVE_QUERY");
        assert!(v["estimate"]["plan"].is_array(), "{v}");

        // 5) `sample` is a SELECT *, so a protected column refuses it in BOTH
        //    modes — the agent is told to name the columns it needs instead.
        for pii in [
            "[connections.pg.pii]\ncolumns = [\"users.email\"]\n",
            "[connections.pg.pii]\ncolumns = [\"users.email\"]\nmode = \"mask\"\n",
        ] {
            let cfg = write_pg_config_with(tmp.path(), port, pii);
            let out = run(tmp.path(), &cfg, &["sample", "pg", "users"]);
            assert_eq!(out.status.code(), Some(5), "{}", stdout(&out));
            let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
            assert_eq!(v["error"]["code"], "NYET");
            assert_eq!(v["error"]["reason"], "PII_COLUMN");
            // An unprotected table still samples.
            let out = run(tmp.path(), &cfg, &["sample", "pg", "sales.orders"]);
            assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
        }

        container.rm().await.unwrap();
    });
}
