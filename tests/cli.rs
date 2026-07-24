//! Integration tests: run the real binary, pin down envelope structure,
//! error codes and exit codes (Д7: the output is an API).

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

/// Command with a clean environment: no real ~/.config, no ambient vars.
fn nyet(home: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_nyet"));
    cmd.env_clear().env("HOME", home);
    cmd
}

fn write_config(dir: &Path, text: &str) -> std::path::PathBuf {
    let path = dir.join("config.toml");
    fs::write(&path, text).unwrap();
    path
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn error_envelope(out: &Output) -> serde_json::Value {
    let v: serde_json::Value = serde_json::from_str(stdout(out).trim()).unwrap();
    assert_eq!(v["v"], 1);
    assert_eq!(v["ok"], false);
    // Every error must carry an actionable hint (Д10).
    assert!(v["error"]["hint"].is_string(), "hint missing: {v}");
    v
}

/// Config with one connection allowed from `dir` and one allowed nowhere.
fn two_conn_config(dir: &Path) -> String {
    format!(
        r#"
[connections.local]
engine = "sqlite"
path = "./dev.db"
allowed_dirs = ["{}"]

[connections.prod]
engine = "postgres"
url = "postgres://nyet_ro@db/app"
password_env = "TEST_DB_PASSWORD"
allowed_dirs = ["/no/such/place"]
"#,
        dir.display()
    )
}

#[test]
fn list_json_shows_only_connections_allowed_from_cwd() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = write_config(tmp.path(), &two_conn_config(tmp.path()));
    let out = nyet(tmp.path())
        .args(["list", "--config"])
        .arg(&cfg)
        .env("TEST_DB_PASSWORD", "hunter2")
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    // Snapshot: exact envelope. No URLs, no credentials — aliases only.
    assert_eq!(
        stdout(&out).trim(),
        r#"{"v":1,"ok":true,"connections":[{"alias":"local","engine":"sqlite"}]}"#
    );
    assert!(!stdout(&out).contains("hunter2"));
    assert!(!stderr(&out).contains("hunter2"));
}

#[test]
fn list_table_puts_envelope_on_stderr() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = write_config(tmp.path(), &two_conn_config(tmp.path()));
    let out = nyet(tmp.path())
        .args(["list", "--format", "table", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(stdout(&out).contains("local"));
    assert!(stdout(&out).contains("sqlite"));
    assert!(stderr(&out).contains(r#"{"v":1,"ok":true}"#));
}

#[test]
fn table_format_error_envelope_goes_to_stderr_stdout_stays_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = write_config(tmp.path(), "not = [valid toml");
    let out = nyet(tmp.path())
        .args(["list", "--format", "table", "--config"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    // Envelope placement is decided by the format, not the outcome.
    assert_eq!(stdout(&out), "");
    // stderr may also carry a permissions warning; the envelope is the last line.
    let all = stderr(&out);
    let line = all.trim().lines().last().unwrap();
    let v: serde_json::Value = serde_json::from_str(line).unwrap();
    assert_eq!(v["ok"], false);
    assert_eq!(v["error"]["code"], "CONFIG_INVALID");
}

#[test]
fn relative_allowed_dirs_entry_is_exit_3() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = write_config(
        tmp.path(),
        "[connections.a]\nengine = \"sqlite\"\nallowed_dirs = [\".\"]\n",
    );
    let out = nyet(tmp.path())
        .args(["list", "--config"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    let v = error_envelope(&out);
    assert_eq!(v["error"]["code"], "CONFIG_INVALID");
    assert!(v["error"]["hint"].as_str().unwrap().contains("absolute"));
}

#[test]
fn toml_error_never_leaks_secrets_from_source_lines() {
    let tmp = tempfile::tempdir().unwrap();
    // Unterminated string: the offending line contains a credential.
    let cfg = write_config(
        tmp.path(),
        "[connections.a]\nengine = \"postgres\"\nurl = \"postgres://user:supersecret@host/db\n",
    );
    let out = nyet(tmp.path())
        .args(["list", "--config"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert!(!stdout(&out).contains("supersecret"), "{}", stdout(&out));
    assert!(!stderr(&out).contains("supersecret"), "{}", stderr(&out));
}

#[test]
fn missing_or_empty_allowed_dirs_denies_everywhere() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = write_config(
        tmp.path(),
        "[connections.absent]\nengine = \"sqlite\"\npath = \"./a.db\"\n\
         [connections.empty]\nengine = \"sqlite\"\npath = \"./b.db\"\nallowed_dirs = []\n",
    );
    let list = nyet(tmp.path())
        .args(["list", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(list.status.code(), Some(0));
    assert_eq!(
        stdout(&list).trim(),
        r#"{"v":1,"ok":true,"connections":[]}"#
    );
    for alias in ["absent", "empty"] {
        let out = nyet(tmp.path())
            .args(["query", alias, "select 1", "--config"])
            .arg(&cfg)
            .current_dir(tmp.path())
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(4), "alias {alias}");
        let v = error_envelope(&out);
        assert_eq!(v["error"]["code"], "DIR_NOT_ALLOWED");
    }
}

#[test]
fn env_var_in_allowed_dirs_is_exit_3() {
    // The env is controlled by the calling agent, so ${VAR} in allowed_dirs
    // is banned outright: "~/${X}" with X="../sibling" (traversal) and
    // "/srv/${P}" with P="" (empty value widens to the parent) both fail.
    for (dirs, var, val) in [("~/${X}", "X", "../sibling"), ("/srv/${P}", "P", "")] {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = write_config(
            tmp.path(),
            &format!("[connections.a]\nengine = \"sqlite\"\nallowed_dirs = [\"{dirs}\"]\n"),
        );
        let out = nyet(tmp.path())
            .args(["list", "--config"])
            .arg(&cfg)
            .env(var, val)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(3), "{dirs}");
        let v = error_envelope(&out);
        assert_eq!(v["error"]["code"], "CONFIG_INVALID");
        assert!(
            v["error"]["hint"].as_str().unwrap().contains("literal"),
            "{v}"
        );
    }
}

#[test]
fn schema_error_never_leaks_values() {
    let tmp = tempfile::tempdir().unwrap();
    // Wrong type: the schema error echoes the value in quotes — must be redacted.
    let cfg = write_config(
        tmp.path(),
        "[connections.a]\nengine = \"sqlite\"\nrow_limit = \"supersecret\"\n",
    );
    let out = nyet(tmp.path())
        .args(["list", "--config"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert!(!stdout(&out).contains("supersecret"), "{}", stdout(&out));
    assert!(!stderr(&out).contains("supersecret"), "{}", stderr(&out));
}

#[test]
fn config_not_found_is_exit_3() {
    let tmp = tempfile::tempdir().unwrap();
    let out = nyet(tmp.path())
        .args(["list", "--config", "/no/such/config.toml"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    let v = error_envelope(&out);
    assert_eq!(v["error"]["code"], "CONFIG_INVALID");
}

#[test]
fn config_path_from_nyet_config_env() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = write_config(tmp.path(), &two_conn_config(tmp.path()));
    let out = nyet(tmp.path())
        .arg("list")
        .env("NYET_CONFIG", &cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn default_config_location_under_home() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join(".config/nyet");
    fs::create_dir_all(&dir).unwrap();
    write_config(&dir, &two_conn_config(tmp.path()));
    let out = nyet(tmp.path())
        .arg("list")
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn unknown_key_is_exit_3() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = write_config(
        tmp.path(),
        "[connections.a]\nengine = \"sqlite\"\ntypo_key = 1\n",
    );
    let out = nyet(tmp.path())
        .args(["list", "--config"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    let v = error_envelope(&out);
    assert_eq!(v["error"]["code"], "CONFIG_INVALID");
    assert!(v["error"]["message"].as_str().unwrap().contains("typo_key"));
}

#[test]
fn missing_env_var_in_config_is_exit_3() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = write_config(
        tmp.path(),
        "[connections.a]\nengine = \"postgres\"\nurl = \"${NYET_TEST_UNSET_VAR}\"\n",
    );
    let out = nyet(tmp.path())
        .args(["list", "--config"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    let v = error_envelope(&out);
    assert_eq!(v["error"]["code"], "CONFIG_INVALID");
    assert!(v["error"]["message"]
        .as_str()
        .unwrap()
        .contains("NYET_TEST_UNSET_VAR"));
}

#[test]
fn query_unknown_alias_is_exit_3_with_known_aliases_hint() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = write_config(tmp.path(), &two_conn_config(tmp.path()));
    let out = nyet(tmp.path())
        .args(["query", "nope", "select 1", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    let v = error_envelope(&out);
    assert_eq!(v["error"]["code"], "CONFIG_INVALID");
    let hint = v["error"]["hint"].as_str().unwrap();
    assert!(hint.contains("local") && hint.contains("prod"), "{hint}");
}

#[test]
fn query_outside_allowed_dirs_is_exit_4() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = write_config(tmp.path(), &two_conn_config(tmp.path()));
    let out = nyet(tmp.path())
        .args(["query", "prod", "select 1", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(4));
    let v = error_envelope(&out);
    assert_eq!(v["error"]["code"], "DIR_NOT_ALLOWED");
    // Hint names the directories the connection is allowed from.
    assert!(v["error"]["hint"]
        .as_str()
        .unwrap()
        .contains("/no/such/place"));
}

#[test]
fn query_unsupported_engine_is_not_implemented_exit_1() {
    let tmp = tempfile::tempdir().unwrap();
    // A postgres connection that IS allowed from cwd: resolution succeeds,
    // the engine is honestly not supported yet. Pins pipeline order too:
    // the engine check fires before the validator, so even SQL the
    // validator would refuse gets NOT_IMPLEMENTED (a NYET with a
    // "fix your SQL" hint would be misleading here).
    let cfg = write_config(
        tmp.path(),
        &format!(
            "[connections.pg]\nengine = \"postgres\"\nurl = \"postgres://u@h/db\"\n\
             allowed_dirs = [\"{}\"]\n",
            tmp.path().display()
        ),
    );
    for sql in ["select 1", "DELETE FROM users", "not sql at all"] {
        let out = nyet(tmp.path())
            .args(["query", "pg", sql, "--config"])
            .arg(&cfg)
            .current_dir(tmp.path())
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1), "{sql}");
        let v = error_envelope(&out);
        assert_eq!(v["error"]["code"], "NOT_IMPLEMENTED", "{sql}");
    }
}

#[test]
fn cli_usage_error_is_exit_2() {
    let tmp = tempfile::tempdir().unwrap();
    let out = nyet(tmp.path()).arg("frobnicate").output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let out = nyet(tmp.path()).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
}

// ---------------------------------------------------------------------------
// nyet query (SQLite end-to-end)
// ---------------------------------------------------------------------------

/// Fixture database: three users.
fn make_db(path: &Path) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    rt.block_on(async {
        use sqlx::ConnectOptions;
        let mut conn = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .connect()
            .await
            .unwrap();
        for sql in [
            "CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT)",
            "INSERT INTO users VALUES (1, 'a@b.c'), (2, 'd@e.f'), (3, NULL)",
        ] {
            sqlx::query(sqlx::AssertSqlSafe(sql.to_string()))
                .execute(&mut conn)
                .await
                .unwrap();
        }
        sqlx::Connection::close(conn).await.unwrap();
    });
}

/// Temp dir with a fixture db and a config whose `db` alias points at it.
/// Extra config text (defaults, more connections) can be appended.
fn sqlite_fixture(extra_config: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("fixture.db");
    make_db(&db);
    let cfg = write_config(
        tmp.path(),
        &format!(
            "{extra_config}\n[connections.db]\nengine = \"sqlite\"\npath = \"{}\"\n\
             allowed_dirs = [\"{}\"]\n",
            db.display(),
            tmp.path().display()
        ),
    );
    (tmp, cfg)
}

fn success_envelope(text: &str) -> serde_json::Value {
    let v: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
    assert_eq!(v["v"], 1);
    assert_eq!(v["ok"], true);
    // duration_ms flaps; pin its presence and type, not its value.
    assert!(v["meta"]["duration_ms"].is_u64(), "{v}");
    v
}

#[test]
fn query_select_json_success() {
    let (tmp, cfg) = sqlite_fixture("");
    let out = nyet(tmp.path())
        .args([
            "query",
            "db",
            "SELECT id, email FROM users ORDER BY id",
            "--config",
        ])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let v = success_envelope(&stdout(&out));
    assert_eq!(
        v["rows"],
        serde_json::json!([
            {"id": 1, "email": "a@b.c"},
            {"id": 2, "email": "d@e.f"},
            {"id": 3, "email": null}
        ])
    );
    assert_eq!(v["meta"]["row_count"], 3);
    assert_eq!(v["meta"]["truncated"], false);
    assert_eq!(v["meta"]["connection"], "db");
    assert!(
        v.get("warnings").is_none(),
        "empty warnings must be omitted"
    );
    // Row objects keep column order: id before email (not alphabetical).
    assert!(
        stdout(&out).contains(r#""rows":[{"id":1,"email":"a@b.c"}"#),
        "{}",
        stdout(&out)
    );
}

#[test]
fn query_table_format_puts_envelope_on_stderr() {
    let (tmp, cfg) = sqlite_fixture("");
    let out = nyet(tmp.path())
        .args([
            "query",
            "db",
            "SELECT id, email FROM users ORDER BY id",
            "--format",
            "table",
            "--config",
        ])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let table = stdout(&out);
    assert!(table.starts_with("id  email\n"), "{table}");
    assert!(table.contains("1   a@b.c"), "{table}");
    let v = success_envelope(stderr(&out).trim().lines().last().unwrap());
    assert_eq!(v["meta"]["row_count"], 3);
    assert!(
        v.get("rows").is_none(),
        "table envelope must not carry rows"
    );
}

#[test]
fn query_write_is_refused_with_nyet_reason_and_hint() {
    let (tmp, cfg) = sqlite_fixture("");
    for (sql, reason) in [
        ("DELETE FROM users", "WRITE_OPERATION"),
        ("DROP TABLE users", "WRITE_OPERATION"),
        ("SELECT 1; SELECT 2", "MULTI_STATEMENT"),
        ("BEGIN", "TXN_CONTROL"),
        ("not sql", "PARSE_FAILED"),
    ] {
        let out = nyet(tmp.path())
            .args(["query", "db", sql, "--config"])
            .arg(&cfg)
            .current_dir(tmp.path())
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(5), "{sql}");
        let v = error_envelope(&out);
        assert_eq!(v["error"]["code"], "NYET", "{sql}");
        assert_eq!(v["error"]["reason"], reason, "{sql}");
    }
    // And the data survived the attempts.
    let out = nyet(tmp.path())
        .args(["query", "db", "SELECT count(*) AS n FROM users", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    let v = success_envelope(&stdout(&out));
    assert_eq!(v["rows"], serde_json::json!([{"n": 3}]));
}

#[test]
fn query_truncation_sets_meta_and_warning() {
    let (tmp, cfg) = sqlite_fixture("");
    let out = nyet(tmp.path())
        .args([
            "query",
            "db",
            "SELECT id FROM users ORDER BY id",
            "--limit",
            "2",
            "--config",
        ])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let v = success_envelope(&stdout(&out));
    assert_eq!(v["rows"], serde_json::json!([{"id": 1}, {"id": 2}]));
    assert_eq!(v["meta"]["row_count"], 2);
    assert_eq!(v["meta"]["truncated"], true);
    assert_eq!(v["warnings"][0]["code"], "TRUNCATED");
    assert!(v["warnings"][0]["message"].is_string());
}

#[test]
fn query_row_limit_from_config_with_flag_override() {
    let (tmp, cfg) = sqlite_fixture("[defaults]\nrow_limit = 1\n");
    // Config default limits to 1 row...
    let out = nyet(tmp.path())
        .args(["query", "db", "SELECT id FROM users", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    let v = success_envelope(&stdout(&out));
    assert_eq!(v["meta"]["row_count"], 1);
    assert_eq!(v["meta"]["truncated"], true);
    // ...and the flag wins over the config.
    let out = nyet(tmp.path())
        .args([
            "query",
            "db",
            "SELECT id FROM users",
            "--limit",
            "10",
            "--config",
        ])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    let v = success_envelope(&stdout(&out));
    assert_eq!(v["meta"]["row_count"], 3);
    assert_eq!(v["meta"]["truncated"], false);
}

#[test]
fn query_timeout_is_exit_8() {
    let (tmp, cfg) = sqlite_fixture("");
    // Unbounded recursive CTE: a legitimate Query for the validator that
    // never finishes — only the timeout can stop it.
    let out = nyet(tmp.path())
        .args([
            "query",
            "db",
            "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c) \
             SELECT count(*) FROM c",
            "--timeout",
            "1",
            "--config",
        ])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(8));
    let v = error_envelope(&out);
    assert_eq!(v["error"]["code"], "TIMEOUT");
}

#[test]
fn query_db_error_is_exit_7() {
    let (tmp, cfg) = sqlite_fixture("");
    let out = nyet(tmp.path())
        .args(["query", "db", "SELECT * FROM no_such_table", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_db_error(&out);
}

fn assert_db_error(out: &Output) {
    assert_eq!(out.status.code(), Some(7));
    let v = error_envelope(out);
    assert_eq!(v["error"]["code"], "DB_ERROR");
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("no_such_table"),
        "{v}"
    );
}

#[test]
fn query_missing_db_file_is_exit_6() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = write_config(
        tmp.path(),
        &format!(
            "[connections.db]\nengine = \"sqlite\"\npath = \"{}/absent.db\"\n\
             allowed_dirs = [\"{}\"]\n",
            tmp.path().display(),
            tmp.path().display()
        ),
    );
    let out = nyet(tmp.path())
        .args(["query", "db", "SELECT 1", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(6));
    let v = error_envelope(&out);
    assert_eq!(v["error"]["code"], "CONNECTION_FAILED");
}

#[test]
fn sqlite_connection_without_path_is_exit_3() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = write_config(
        tmp.path(),
        &format!(
            "[connections.db]\nengine = \"sqlite\"\nallowed_dirs = [\"{}\"]\n",
            tmp.path().display()
        ),
    );
    let out = nyet(tmp.path())
        .args(["query", "db", "SELECT 1", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    let v = error_envelope(&out);
    assert_eq!(v["error"]["code"], "CONFIG_INVALID");
    assert!(v["error"]["hint"].as_str().unwrap().contains("path"));
}

#[test]
fn defaults_format_applies_to_query_and_list_flag_wins() {
    let (tmp, cfg) = sqlite_fixture("[defaults]\nformat = \"table\"\n");
    // query without --format: table on stdout, envelope on stderr.
    let out = nyet(tmp.path())
        .args([
            "query",
            "db",
            "SELECT id FROM users ORDER BY id",
            "--config",
        ])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(stdout(&out).starts_with("id\n"), "{}", stdout(&out));
    success_envelope(stderr(&out).trim().lines().last().unwrap());
    // list without --format: table too.
    let out = nyet(tmp.path())
        .args(["list", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert!(stdout(&out).starts_with("ALIAS"), "{}", stdout(&out));
    // --format json beats the config default.
    let out = nyet(tmp.path())
        .args([
            "query",
            "db",
            "SELECT id FROM users",
            "--format",
            "json",
            "--config",
        ])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    success_envelope(&stdout(&out));
}

#[test]
fn unsupported_defaults_format_is_exit_3() {
    let (tmp, cfg) = sqlite_fixture("[defaults]\nformat = \"csv\"\n");
    let out = nyet(tmp.path())
        .args(["query", "db", "SELECT 1", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    let v = error_envelope(&out);
    assert_eq!(v["error"]["code"], "CONFIG_INVALID");
}

#[test]
fn scoping_fires_before_the_validator() {
    // A write query against a connection denied from cwd answers with the
    // scoping error (exit 4), not a SQL lecture (exit 5) — pins the order.
    let tmp = tempfile::tempdir().unwrap();
    let cfg = write_config(
        tmp.path(),
        "[connections.far]\nengine = \"sqlite\"\npath = \"/tmp/x.db\"\n\
         allowed_dirs = [\"/no/such/place\"]\n",
    );
    let out = nyet(tmp.path())
        .args(["query", "far", "DELETE FROM users", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(4));
    let v = error_envelope(&out);
    assert_eq!(v["error"]["code"], "DIR_NOT_ALLOWED");
}

#[test]
fn defaults_format_table_routes_early_errors_to_stderr() {
    // [defaults].format is settled right after the config parses, so even
    // an unknown-alias error routes by it: stdout stays empty (data-only),
    // the envelope goes to stderr.
    let (tmp, cfg) = sqlite_fixture("[defaults]\nformat = \"table\"\n");
    let out = nyet(tmp.path())
        .args(["query", "nope", "SELECT 1", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(stdout(&out), "");
    let all = stderr(&out);
    let v: serde_json::Value = serde_json::from_str(all.trim().lines().last().unwrap()).unwrap();
    assert_eq!(v["error"]["code"], "CONFIG_INVALID");
}

#[test]
fn zero_limits_in_config_are_exit_3() {
    for line in ["row_limit = 0", "timeout_secs = 0"] {
        let (tmp, cfg) = sqlite_fixture(&format!("[defaults]\n{line}\n"));
        let out = nyet(tmp.path())
            .args(["list", "--config"])
            .arg(&cfg)
            .current_dir(tmp.path())
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(3), "{line}");
        let v = error_envelope(&out);
        assert_eq!(v["error"]["code"], "CONFIG_INVALID");
        assert!(v["error"]["hint"].as_str().unwrap().contains("at least 1"));
    }
}

#[test]
fn zero_limit_flags_are_usage_errors_exit_2() {
    let (tmp, cfg) = sqlite_fixture("");
    for flag in ["--limit", "--timeout"] {
        let out = nyet(tmp.path())
            .args(["query", "db", "SELECT 1", flag, "0", "--config"])
            .arg(&cfg)
            .current_dir(tmp.path())
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{flag}");
    }
}

#[test]
fn duplicate_column_names_produce_a_warning() {
    let (tmp, cfg) = sqlite_fixture("");
    let out = nyet(tmp.path())
        .args(["query", "db", "SELECT 1 AS a, 2 AS a, 3 AS b", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let v = success_envelope(&stdout(&out));
    let warning = &v["warnings"][0];
    assert_eq!(warning["code"], "DUPLICATE_COLUMNS");
    let msg = warning["message"].as_str().unwrap();
    assert!(msg.contains('a') && msg.contains("AS"), "{msg}");
}

#[test]
fn empty_result_table_format_still_prints_the_header() {
    let (tmp, cfg) = sqlite_fixture("");
    let out = nyet(tmp.path())
        .args([
            "query",
            "db",
            "SELECT id, email FROM users WHERE 0 = 1",
            "--format",
            "table",
            "--config",
        ])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(stdout(&out), "id  email\n");
}

#[test]
fn nyet_refusal_with_table_format_goes_to_stderr() {
    let (tmp, cfg) = sqlite_fixture("");
    let out = nyet(tmp.path())
        .args([
            "query",
            "db",
            "DELETE FROM users",
            "--format",
            "table",
            "--config",
        ])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(5));
    // Envelope placement is decided by the format, not the outcome.
    assert_eq!(stdout(&out), "");
    let line = stderr(&out);
    let v: serde_json::Value = serde_json::from_str(line.trim().lines().last().unwrap()).unwrap();
    assert_eq!(v["error"]["code"], "NYET");
    assert_eq!(v["error"]["reason"], "WRITE_OPERATION");
}

#[cfg(unix)]
#[test]
fn loose_permissions_warn_on_stderr_but_do_not_fail() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let cfg = write_config(tmp.path(), &two_conn_config(tmp.path()));
    fs::set_permissions(&cfg, fs::Permissions::from_mode(0o644)).unwrap();
    let out = nyet(tmp.path())
        .args(["list", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(stderr(&out).contains("warning"), "{}", stderr(&out));

    // Tight permissions: no warning.
    fs::set_permissions(&cfg, fs::Permissions::from_mode(0o600)).unwrap();
    let out = nyet(tmp.path())
        .args(["list", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert!(!stderr(&out).contains("warning"));
}
