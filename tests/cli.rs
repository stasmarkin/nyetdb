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
    // A redis connection that IS allowed from cwd: resolution succeeds, the
    // engine is honestly not supported yet (redis lands in a later release).
    // Pins pipeline order too: the engine check fires before the validator,
    // so even SQL the validator would refuse gets NOT_IMPLEMENTED (a NYET
    // with a "fix your SQL" hint would be misleading here).
    let cfg = write_config(
        tmp.path(),
        &format!(
            "[connections.r]\nengine = \"redis\"\nurl = \"redis://h:6379\"\n\
             allowed_dirs = [\"{}\"]\n",
            tmp.path().display()
        ),
    );
    for sql in ["select 1", "DELETE FROM users", "not sql at all"] {
        let out = nyet(tmp.path())
            .args(["query", "r", sql, "--config"])
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

/// The config owner's ceilings on what the agent may spend: `--limit` and
/// `--timeout` beat the config, but `max_row_limit` / `max_timeout_secs` beat
/// the flags. Clamping is silent — the effective limit shows up as the usual
/// TRUNCATED / TIMEOUT answer.
#[test]
fn config_ceilings_clamp_the_flags() {
    let (tmp, cfg) = sqlite_fixture("[defaults]\nmax_row_limit = 2\nmax_timeout_secs = 1\n");
    // --limit 999999 against max_row_limit = 2: two rows and TRUNCATED.
    let out = nyet(tmp.path())
        .args([
            "query",
            "db",
            "SELECT id FROM users ORDER BY id",
            "--limit",
            "999999",
            "--config",
        ])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let v = success_envelope(&stdout(&out));
    assert_eq!(v["meta"]["row_count"], 2, "{v}");
    assert_eq!(v["meta"]["truncated"], true);
    assert_eq!(v["warnings"][0]["code"], "TRUNCATED");
    // --timeout 999999 against max_timeout_secs = 1: the query is cut at the
    // ceiling (an unbounded recursive CTE would otherwise never return).
    let out = nyet(tmp.path())
        .args([
            "query",
            "db",
            "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c)              SELECT count(*) FROM c",
            "--timeout",
            "999999",
            "--config",
        ])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(8), "{}", stdout(&out));
    assert_eq!(error_envelope(&out)["error"]["code"], "TIMEOUT");
    // Without ceilings the flags win, exactly as before.
    let (tmp, cfg) = sqlite_fixture("");
    let out = nyet(tmp.path())
        .args([
            "query",
            "db",
            "SELECT id FROM users ORDER BY id",
            "--limit",
            "999999",
            "--config",
        ])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(success_envelope(&stdout(&out))["meta"]["row_count"], 3);
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
fn ssh_without_host_or_remote_is_exit_3() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = write_config(
        tmp.path(),
        &format!(
            "[connections.db]\nengine = \"postgres\"\nurl = \"postgres://u@h/db\"\n\
             allowed_dirs = [\"{}\"]\n[connections.db.ssh]\nremote = \"db:5432\"\n",
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
    assert!(v["error"]["message"].as_str().unwrap().contains("host"));
}

#[test]
fn sqlite_with_ssh_is_exit_3() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = write_config(
        tmp.path(),
        &format!(
            "[connections.db]\nengine = \"sqlite\"\npath = \"./x.db\"\n\
             allowed_dirs = [\"{}\"]\n[connections.db.ssh]\n\
             host = \"deploy@bastion:22\"\nremote = \"db:5432\"\n",
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
    assert!(v["error"]["hint"].as_str().unwrap().contains("SQLite"));
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
    let (tmp, cfg) = sqlite_fixture("[defaults]\nformat = \"xml\"\n");
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
fn defaults_format_csv_routes_config_error_envelope_to_stderr() {
    // The routing format is resolved from a raw peek of [defaults].format
    // BEFORE the semantic config parse, so a config error (row_limit = 0)
    // under format = "csv" still routes: stdout is data-only (empty here),
    // the error envelope goes to stderr. Exit 3 either way.
    let (tmp, cfg) = sqlite_fixture("[defaults]\nformat = \"csv\"\nrow_limit = 0\n");
    let out = nyet(tmp.path())
        .args(["query", "db", "SELECT 1", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(stdout(&out), "");
    let all = stderr(&out);
    let v: serde_json::Value = serde_json::from_str(all.trim().lines().last().unwrap()).unwrap();
    assert_eq!(v["ok"], false);
    assert_eq!(v["error"]["code"], "CONFIG_INVALID");
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

#[test]
fn query_jsonl_streams_rows_on_stdout_envelope_on_stderr() {
    let (tmp, cfg) = sqlite_fixture("");
    let out = nyet(tmp.path())
        .args([
            "query",
            "db",
            "SELECT id, email FROM users ORDER BY id",
            "--format",
            "jsonl",
            "--config",
        ])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    // Snapshot: one compact JSON object per row, column order preserved.
    assert_eq!(
        stdout(&out),
        "{\"id\":1,\"email\":\"a@b.c\"}\n{\"id\":2,\"email\":\"d@e.f\"}\n{\"id\":3,\"email\":null}\n"
    );
    let v = success_envelope(stderr(&out).trim().lines().last().unwrap());
    assert_eq!(v["meta"]["row_count"], 3);
    assert!(
        v.get("rows").is_none(),
        "jsonl envelope must not carry rows"
    );
}

#[test]
fn query_jsonl_error_keeps_stdout_empty() {
    let (tmp, cfg) = sqlite_fixture("");
    let out = nyet(tmp.path())
        .args([
            "query",
            "db",
            "DELETE FROM users",
            "--format",
            "jsonl",
            "--config",
        ])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(5));
    // Envelope placement is decided by the format, not the outcome.
    assert_eq!(stdout(&out), "");
    let all = stderr(&out);
    let v: serde_json::Value = serde_json::from_str(all.trim().lines().last().unwrap()).unwrap();
    assert_eq!(v["error"]["code"], "NYET");
    assert_eq!(v["error"]["reason"], "WRITE_OPERATION");
}

#[test]
fn query_csv_quotes_commas_quotes_and_newlines() {
    let (tmp, cfg) = sqlite_fixture("");
    // A fixture row exercising every RFC 4180 quoting trigger + NULL.
    let sql = "SELECT 'com,ma' AS a, 'qu\"ote' AS b, 'li' || char(10) || 'ne' AS c, \
               NULL AS d, 42 AS e";
    let out = nyet(tmp.path())
        .args(["query", "db", sql, "--format", "csv", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    // Snapshot: header + one record; NULL renders as an empty field.
    assert_eq!(
        stdout(&out),
        "a,b,c,d,e\n\"com,ma\",\"qu\"\"ote\",\"li\nne\",,42\n"
    );
    let v = success_envelope(stderr(&out).trim().lines().last().unwrap());
    assert_eq!(v["meta"]["row_count"], 1);
}

#[test]
fn query_csv_error_keeps_stdout_empty() {
    let (tmp, cfg) = sqlite_fixture("");
    let out = nyet(tmp.path())
        .args([
            "query",
            "db",
            "SELECT * FROM no_such_table",
            "--format",
            "csv",
            "--config",
        ])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(7));
    assert_eq!(stdout(&out), "");
    let all = stderr(&out);
    let v: serde_json::Value = serde_json::from_str(all.trim().lines().last().unwrap()).unwrap();
    assert_eq!(v["error"]["code"], "DB_ERROR");
}

#[test]
fn list_rejects_jsonl_and_csv_flags_as_usage_errors() {
    // DESIGN gives list only json|table; jsonl/csv are row-stream formats.
    let (tmp, cfg) = sqlite_fixture("");
    for format in ["jsonl", "csv"] {
        let out = nyet(tmp.path())
            .args(["list", "--format", format, "--config"])
            .arg(&cfg)
            .current_dir(tmp.path())
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{format}");
    }
}

#[test]
fn list_degrades_jsonl_config_default_to_json() {
    // [defaults].format = "jsonl" serves query workflows; list has no row
    // stream, so it falls back to json instead of failing.
    let (tmp, cfg) = sqlite_fixture("[defaults]\nformat = \"jsonl\"\n");
    let out = nyet(tmp.path())
        .args(["list", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
    assert_eq!(v["ok"], true);
    assert!(v["connections"].is_array(), "{v}");
}

#[test]
fn list_degrades_csv_config_default_to_json() {
    // Same degrade path for csv (symmetric with the jsonl case): list has no
    // row stream, so a csv [defaults].format falls back to a json envelope.
    let (tmp, cfg) = sqlite_fixture("[defaults]\nformat = \"csv\"\n");
    let out = nyet(tmp.path())
        .args(["list", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
    assert_eq!(v["ok"], true);
    assert!(v["connections"].is_array(), "{v}");
}

#[test]
fn unicode_stripped_query_succeeds_with_warning() {
    let (tmp, cfg) = sqlite_fixture("");
    // Zero-width joiner inside SELECT: stripped, validated, executed.
    let out = nyet(tmp.path())
        .args([
            "query",
            "db",
            "SEL\u{200D}ECT count(*) AS n FROM users",
            "--config",
        ])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let v = success_envelope(&stdout(&out));
    assert_eq!(v["rows"], serde_json::json!([{"n": 3}]));
    assert_eq!(v["warnings"][0]["code"], "UNICODE_STRIPPED");
    assert!(v["warnings"][0]["message"].is_string());
}

#[test]
fn denied_function_is_exit_5_with_reason_and_hint() {
    let (tmp, cfg) = sqlite_fixture("");
    let out = nyet(tmp.path())
        .args([
            "query",
            "db",
            "SELECT load_extension('/tmp/evil.so')",
            "--config",
        ])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(5));
    let v = error_envelope(&out);
    assert_eq!(v["error"]["code"], "NYET");
    assert_eq!(v["error"]["reason"], "DENIED_FUNCTION");
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("load_extension"),
        "{v}"
    );
    assert!(
        v["error"]["hint"]
            .as_str()
            .unwrap()
            .contains("allow_functions"),
        "{v}"
    );
}

#[test]
fn config_deny_functions_blocks_and_allow_functions_permits() {
    // deny_functions adds a builtin SQLite function to the denylist...
    let (tmp, cfg) = sqlite_fixture("");
    let cfg_text = format!(
        "{}\n[connections.db.validator]\ndeny_functions = [\"abs\"]\n",
        fs::read_to_string(&cfg).unwrap()
    );
    fs::write(&cfg, cfg_text).unwrap();
    let out = nyet(tmp.path())
        .args(["query", "db", "SELECT abs(-1) AS a", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(5));
    let v = error_envelope(&out);
    assert_eq!(v["error"]["reason"], "DENIED_FUNCTION");

    // ...allow_functions removes a builtin denylist entry: the validator
    // passes and the refusal (if any) now comes from the database, not nyet.
    let (tmp, cfg) = sqlite_fixture("");
    let cfg_text = format!(
        "{}\n[connections.db.validator]\nallow_functions = [\"load_extension\"]\n",
        fs::read_to_string(&cfg).unwrap()
    );
    fs::write(&cfg, cfg_text).unwrap();
    let out = nyet(tmp.path())
        .args([
            "query",
            "db",
            "SELECT load_extension('/no/such.so')",
            "--config",
        ])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_ne!(out.status.code(), Some(5), "validator must not refuse");
    let all = stdout(&out);
    let v: serde_json::Value = serde_json::from_str(all.trim()).unwrap();
    assert_ne!(v["error"]["code"], "NYET", "{v}");
}

// ---------------------------------------------------------------------------
// nyet schema (SQLite end-to-end)
// ---------------------------------------------------------------------------

/// Build a database from raw DDL and a config pointing an alias `db` at it.
fn schema_fixture(ddl: &[&str]) -> (tempfile::TempDir, std::path::PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("schema.db");
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    rt.block_on(async {
        use sqlx::ConnectOptions;
        let mut conn = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&db)
            .create_if_missing(true)
            .connect()
            .await
            .unwrap();
        for sql in ddl {
            sqlx::query(sqlx::AssertSqlSafe(sql.to_string()))
                .execute(&mut conn)
                .await
                .unwrap();
        }
        sqlx::Connection::close(conn).await.unwrap();
    });
    let cfg = write_config(
        tmp.path(),
        &format!(
            "[connections.db]\nengine = \"sqlite\"\npath = \"{}\"\nallowed_dirs = [\"{}\"]\n",
            db.display(),
            tmp.path().display()
        ),
    );
    (tmp, cfg)
}

/// Tables covering every presentation rule: composite pk + composite fk,
/// a single-column UNIQUE constraint, a multi-column unique index, a plain
/// index, a defaulted column, an implicit `REFERENCES` and a view.
const SCHEMA_DDL: &[&str] = &[
    "CREATE TABLE orgs (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE)",
    "CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE, \
     org_id INTEGER REFERENCES orgs, created_at TEXT DEFAULT CURRENT_TIMESTAMP)",
    "CREATE INDEX users_org_idx ON users(org_id)",
    "CREATE TABLE memberships (org_id INTEGER NOT NULL, user_id INTEGER NOT NULL, role TEXT, \
     PRIMARY KEY (org_id, user_id), FOREIGN KEY (org_id, user_id) REFERENCES users(id, email))",
    "CREATE UNIQUE INDEX memberships_role_idx ON memberships(role, org_id)",
    "CREATE VIEW v_active AS SELECT id, email FROM users WHERE org_id IS NOT NULL",
];

#[test]
fn schema_json_pins_the_full_shape() {
    let (tmp, cfg) = schema_fixture(SCHEMA_DDL);
    let out = nyet(tmp.path())
        .args(["schema", "db", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
    assert_eq!(v["v"], 1);
    assert_eq!(v["ok"], true);
    assert_eq!(v["meta"]["table_count"], 4);
    assert_eq!(v["meta"]["connection"], "db");
    assert!(v["meta"]["duration_ms"].is_u64());
    assert!(v.get("warnings").is_none(), "no warnings expected: {v}");
    let tables = v["schema"]["tables"].as_array().unwrap();
    // Ordered by name (deterministic), views included.
    let names: Vec<&str> = tables.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["memberships", "orgs", "users", "v_active"]);

    // Composite primary key marks every member; the composite fk keeps order;
    // the multi-column unique index stays an index (unique: true).
    assert_eq!(
        tables[0],
        serde_json::json!({
            "name": "memberships", "kind": "table",
            "columns": [
                {"name": "org_id", "type": "INTEGER", "nullable": false, "pk": true},
                {"name": "user_id", "type": "INTEGER", "nullable": false, "pk": true},
                {"name": "role", "type": "TEXT", "nullable": true}
            ],
            "indexes": [{"name": "memberships_role_idx", "columns": ["role", "org_id"],
                         "unique": true}],
            "fks": [{"columns": ["org_id", "user_id"], "ref_table": "users",
                     "ref_columns": ["id", "email"]}]
        })
    );
    // A single-column UNIQUE becomes a column flag, its backing index is gone;
    // `REFERENCES orgs` (no column list) resolves to the parent's primary key;
    // a defaulted column reports the default verbatim.
    assert_eq!(
        tables[2],
        serde_json::json!({
            "name": "users", "kind": "table",
            "columns": [
                {"name": "id", "type": "INTEGER", "nullable": false, "pk": true},
                {"name": "email", "type": "TEXT", "nullable": false, "unique": true},
                {"name": "org_id", "type": "INTEGER", "nullable": true},
                {"name": "created_at", "type": "TEXT", "nullable": true,
                 "default": "CURRENT_TIMESTAMP"}
            ],
            "indexes": [{"name": "users_org_idx", "columns": ["org_id"]}],
            "fks": [{"columns": ["org_id"], "ref_table": "orgs", "ref_columns": ["id"]}]
        })
    );
    // A view carries columns and neither indexes nor fks.
    assert_eq!(tables[3]["kind"], "view");
    assert!(tables[3]["columns"].is_array());
    assert!(tables[3].get("indexes").is_none());
    assert!(tables[3].get("fks").is_none());
}

#[test]
fn schema_one_table_is_always_detailed() {
    let (tmp, cfg) = schema_fixture(SCHEMA_DDL);
    let out = nyet(tmp.path())
        .args(["schema", "db", "users", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
    assert_eq!(v["meta"]["table_count"], 1);
    let tables = v["schema"]["tables"].as_array().unwrap();
    assert_eq!(tables.len(), 1);
    assert_eq!(tables[0]["name"], "users");
    assert!(tables[0]["columns"].is_array());
}

#[test]
fn schema_listing_past_the_detail_limit_is_names_only_with_a_warning() {
    // 51 objects (50 tables + a view) exceed the 50-object detail limit.
    let mut ddl: Vec<String> = (0..50)
        .map(|i| format!("CREATE TABLE t{i:02} (id INTEGER)"))
        .collect();
    ddl.push("CREATE VIEW v AS SELECT 1 AS x".to_string());
    let refs: Vec<&str> = ddl.iter().map(String::as_str).collect();
    let (tmp, cfg) = schema_fixture(&refs);
    let out = nyet(tmp.path())
        .args(["schema", "db", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
    assert_eq!(v["meta"]["table_count"], 51);
    let tables = v["schema"]["tables"].as_array().unwrap();
    assert_eq!(tables.len(), 51);
    // Names and kinds only — nothing else.
    assert_eq!(
        tables[0],
        serde_json::json!({"name": "t00", "kind": "table"})
    );
    assert_eq!(tables[50], serde_json::json!({"name": "v", "kind": "view"}));
    assert_eq!(v["warnings"][0]["code"], "SCHEMA_TRUNCATED");
    let message = v["warnings"][0]["message"].as_str().unwrap();
    // Actionable (Д10): it names the way to the details.
    assert!(message.contains("nyet schema db <table>"), "{message}");

    // ...and asking for one of them still gives the full detail.
    let out = nyet(tmp.path())
        .args(["schema", "db", "t07", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
    assert!(v.get("warnings").is_none(), "{v}");
    assert_eq!(v["schema"]["tables"][0]["columns"][0]["name"], "id");
}

#[test]
fn schema_unknown_table_is_exit_7_and_sql_injection_is_just_a_missing_name() {
    let (tmp, cfg) = schema_fixture(SCHEMA_DDL);
    // The [table] argument is agent input: it is compared against the catalog,
    // never interpolated — an injection attempt is only a name that matches
    // nothing, and the fixture survives it.
    for arg in [
        "nope",
        "users; DROP TABLE orgs",
        "users'--",
        "users' UNION SELECT 1--",
        "') OR 1=1--",
    ] {
        let out = nyet(tmp.path())
            .args(["schema", "db", arg, "--config"])
            .arg(&cfg)
            .current_dir(tmp.path())
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(7), "{arg}: {}", stdout(&out));
        let v = error_envelope(&out);
        assert_eq!(v["error"]["code"], "DB_ERROR", "{arg}");
        assert!(
            v["error"]["message"]
                .as_str()
                .unwrap()
                .contains("not found"),
            "{v}"
        );
        assert!(
            v["error"]["hint"]
                .as_str()
                .unwrap()
                .contains("nyet schema db"),
            "{v}"
        );
    }
    // Every table is still there.
    let out = nyet(tmp.path())
        .args(["schema", "db", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
    assert_eq!(v["meta"]["table_count"], 4);
}

/// The cases where a naive reading of the catalog would invent a key that does
/// not exist (or hide a column that does).
#[test]
fn schema_sqlite_edge_cases_are_not_faked() {
    let (tmp, cfg) = schema_fixture(&[
        "CREATE TABLE t (a TEXT, b TEXT, c TEXT, d TEXT UNIQUE, \
         total INTEGER GENERATED ALWAYS AS (length(a)) STORED)",
        // An expression key part: the index is two-part, so it must NOT look
        // single-column (which would fold into a bogus `unique` on c).
        "CREATE UNIQUE INDEX t_expr_idx ON t(lower(b), c)",
        // Partial: uniqueness holds only for the predicate rows.
        "CREATE UNIQUE INDEX t_partial_idx ON t(a) WHERE c IS NOT NULL",
        // An inline multi-column UNIQUE — SQLite backs it with an autoindex,
        // which survives (the column flags cannot express a composite key).
        "CREATE TABLE u (x TEXT, y TEXT, UNIQUE (x, y))",
        // A parent with no primary key: the reference cannot be resolved.
        "CREATE TABLE p (a TEXT)",
        "CREATE TABLE ch (p_id INTEGER REFERENCES p)",
    ]);
    let out = nyet(tmp.path())
        .args(["schema", "db", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
    let tables = v["schema"]["tables"].as_array().unwrap();
    let table = |name: &str| {
        tables
            .iter()
            .find(|t| t["name"] == name)
            .unwrap_or_else(|| panic!("{name} missing: {v}"))
            .clone()
    };

    let t = table("t");
    // A STORED generated column is a readable column (pragma_table_info hides
    // it, table_xinfo does not).
    assert_eq!(
        t["columns"][4],
        serde_json::json!({"name": "total", "type": "INTEGER", "nullable": true})
    );
    // The single-column UNIQUE constraint folded into the column flag...
    assert_eq!(t["columns"][3]["name"], "d");
    assert_eq!(t["columns"][3]["unique"], true);
    // ...but neither the expression index nor the partial one may claim a key.
    assert!(t["columns"][0].get("unique").is_none(), "a: {t}");
    assert!(t["columns"][2].get("unique").is_none(), "c: {t}");
    assert_eq!(
        t["indexes"],
        serde_json::json!([
            {"name": "t_partial_idx", "columns": ["a"]},
            {"name": "t_expr_idx", "columns": ["(expression)", "c"], "unique": true}
        ])
    );

    // The inline composite UNIQUE stays an index, autoindex name and all.
    assert_eq!(
        table("u")["indexes"],
        serde_json::json!([{"name": "sqlite_autoindex_u_1", "columns": ["x", "y"],
                            "unique": true}])
    );
    // An unresolvable parent key is reported empty, not invented.
    assert_eq!(
        table("ch")["fks"],
        serde_json::json!([{"columns": ["p_id"], "ref_table": "p", "ref_columns": []}])
    );
}

#[test]
fn schema_table_argument_is_case_insensitive_like_sqlite_itself() {
    // `SELECT * FROM USERS` works against `users`, so `nyet schema db USERS`
    // must too — the argument follows the engine's own name resolution.
    let (tmp, cfg) = schema_fixture(SCHEMA_DDL);
    for arg in ["users", "USERS", "Users"] {
        let out = nyet(tmp.path())
            .args(["schema", "db", arg, "--config"])
            .arg(&cfg)
            .current_dir(tmp.path())
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(0), "{arg}: {}", stdout(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["schema"]["tables"][0]["name"], "users", "{arg}");
    }
}

#[test]
fn schema_table_format_puts_the_envelope_on_stderr() {
    let (tmp, cfg) = schema_fixture(SCHEMA_DDL);
    let out = nyet(tmp.path())
        .args(["schema", "db", "orgs", "--format", "table", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(
        stdout(&out),
        "orgs table\n  id    INTEGER  not null  pk\n  name  TEXT     not null  unique\n"
    );
    let v: serde_json::Value =
        serde_json::from_str(stderr(&out).trim().lines().last().unwrap()).unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["meta"]["table_count"], 1);
    assert!(
        v.get("schema").is_none(),
        "table envelope carries no schema"
    );
}

#[test]
fn schema_mirrors_the_list_format_conventions() {
    // json|table only (jsonl/csv are row-stream formats -> usage error)...
    let (tmp, cfg) = schema_fixture(SCHEMA_DDL);
    for format in ["jsonl", "csv"] {
        let out = nyet(tmp.path())
            .args(["schema", "db", "--format", format, "--config"])
            .arg(&cfg)
            .current_dir(tmp.path())
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{format}");
    }
    // ...and a jsonl/csv [defaults].format degrades to json instead of failing.
    for format in ["jsonl", "csv"] {
        let (tmp, cfg) = schema_fixture(SCHEMA_DDL);
        let text = format!(
            "[defaults]\nformat = \"{format}\"\n{}",
            fs::read_to_string(&cfg).unwrap()
        );
        fs::write(&cfg, text).unwrap();
        let out = nyet(tmp.path())
            .args(["schema", "db", "--config"])
            .arg(&cfg)
            .current_dir(tmp.path())
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(0), "{format}: {}", stderr(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert!(v["schema"]["tables"].is_array(), "{v}");
    }
}

#[test]
fn explain_on_sqlite_is_honest_about_having_no_estimate() {
    let (tmp, cfg) = sqlite_fixture("");
    let out = nyet(tmp.path())
        .args([
            "explain",
            "db",
            "SELECT id, email FROM users ORDER BY email",
            "--config",
        ])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let v = success_envelope(&stdout(&out));
    // SQLite publishes a plan but NO cost/row estimate, so nyet reports the
    // plan and says there is nothing to judge — no invented pseudo-metric
    // (UX-7), no threshold, no cost/rows keys at all.
    assert_eq!(v["estimate"]["mode"], "off");
    assert_eq!(v["estimate"]["verdict"], "no_estimate");
    for absent in ["cost", "rows", "threshold"] {
        assert!(v["estimate"].get(absent).is_none(), "{absent}: {v}");
    }
    let plan = v["estimate"]["plan"].as_array().unwrap();
    assert!(
        plan.iter().any(|line| line
            .as_str()
            .is_some_and(|l| l.contains("SCAN") && l.contains("users"))),
        "{v}"
    );
    assert_eq!(v["meta"]["connection"], "db");

    // table format: the plan for human eyes on stdout, envelope on stderr.
    let out = nyet(tmp.path())
        .args([
            "explain",
            "db",
            "SELECT id FROM users",
            "--format",
            "table",
            "--config",
        ])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(
        stdout(&out).starts_with("verdict: no_estimate (mode off)\n"),
        "{}",
        stdout(&out)
    );
    assert!(stdout(&out).contains("users"), "{}", stdout(&out));
    let env: serde_json::Value =
        serde_json::from_str(stderr(&out).trim().lines().last().unwrap()).unwrap();
    assert_eq!(env["ok"], true);
    assert!(env.get("estimate").is_none(), "{env}");

    // The validator runs first and fails closed the same way as for `query`:
    // planning a write is refused before anything reaches the database.
    let out = nyet(tmp.path())
        .args(["explain", "db", "DELETE FROM users", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(5), "{}", stdout(&out));
    let v = error_envelope(&out);
    assert_eq!(v["error"]["code"], "NYET");
    assert_eq!(v["error"]["reason"], "WRITE_OPERATION");
    // ...and so is an EXPLAIN ANALYZE over a write (ANALYZE would run it).
    let out = nyet(tmp.path())
        .args([
            "explain",
            "db",
            "EXPLAIN ANALYZE DELETE FROM users",
            "--config",
        ])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(5), "{}", stdout(&out));
    assert_eq!(error_envelope(&out)["error"]["reason"], "WRITE_OPERATION");

    // A plain query still runs exactly as before — sqlite has no guardrail, so
    // nothing changed for it (and no GUARDRAIL_SKIPPED noise either).
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
    let v = success_envelope(&stdout(&out));
    assert_eq!(v["meta"]["row_count"], 3);
    assert!(v.get("warnings").is_none(), "{v}");
}

/// A guardrail mode the engine cannot honor must fail LOUD at config parse
/// (exit 3) — never degrade silently to "no guardrail", which would leave the
/// human believing in protection that is not there (UX-1/UX-7).
#[test]
fn a_guardrail_mode_sqlite_cannot_honor_is_a_config_error() {
    // Config parsing owns this rule and the per-engine matrix is unit-tested
    // (src/guardrail.rs, src/config.rs); one run through the binary is enough to
    // pin the exit code and the envelope.
    let (tmp, cfg) = sqlite_fixture("[connections.db.guardrail]\nmode = \"rows\"\n");
    let out = nyet(tmp.path())
        .args(["query", "db", "SELECT 1", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3), "{}", stdout(&out));
    let v = error_envelope(&out);
    assert_eq!(v["error"]["code"], "CONFIG_INVALID");
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("guardrail"),
        "{v}"
    );
    // An explicit "off" is accepted (the sqlite default anyway).
    let (tmp, cfg) = sqlite_fixture("[connections.db.guardrail]\nmode = \"off\"\n");
    let out = nyet(tmp.path())
        .args(["query", "db", "SELECT 1 AS n", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
}

#[test]
fn explain_pipeline_order_matches_query() {
    // alias -> scoping -> engine support -> validator, exactly like query.
    let tmp = tempfile::tempdir().unwrap();
    let cfg = write_config(tmp.path(), &two_conn_config(tmp.path()));
    for (alias, code, expected) in [
        ("nope", 3, "CONFIG_INVALID"),
        ("prod", 4, "DIR_NOT_ALLOWED"),
    ] {
        let out = nyet(tmp.path())
            .args(["explain", alias, "SELECT 1", "--config"])
            .arg(&cfg)
            .current_dir(tmp.path())
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(code), "{alias}: {}", stdout(&out));
        assert_eq!(error_envelope(&out)["error"]["code"], expected);
    }
    // An unsupported engine answers before the validator would.
    let cfg = write_config(
        tmp.path(),
        &format!(
            "[connections.r]\nengine = \"redis\"\nurl = \"redis://h:6379\"\n\
             allowed_dirs = [\"{}\"]\n",
            tmp.path().display()
        ),
    );
    let out = nyet(tmp.path())
        .args(["explain", "r", "DELETE FROM t", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert_eq!(error_envelope(&out)["error"]["code"], "NOT_IMPLEMENTED");
}

#[test]
fn schema_pipeline_order_matches_query() {
    // alias -> scoping -> engine support, exactly like query.
    let tmp = tempfile::tempdir().unwrap();
    let cfg = write_config(tmp.path(), &two_conn_config(tmp.path()));
    // Unknown alias -> exit 3.
    let out = nyet(tmp.path())
        .args(["schema", "nope", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(error_envelope(&out)["error"]["code"], "CONFIG_INVALID");
    // Known alias, denied from cwd -> exit 4.
    let out = nyet(tmp.path())
        .args(["schema", "prod", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(4));
    assert_eq!(error_envelope(&out)["error"]["code"], "DIR_NOT_ALLOWED");
    // Allowed, but the engine is not supported yet -> exit 1.
    let cfg = write_config(
        tmp.path(),
        &format!(
            "[connections.r]\nengine = \"redis\"\nurl = \"redis://h:6379\"\n\
             allowed_dirs = [\"{}\"]\n",
            tmp.path().display()
        ),
    );
    let out = nyet(tmp.path())
        .args(["schema", "r", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(error_envelope(&out)["error"]["code"], "NOT_IMPLEMENTED");
    // A missing database file is a connection failure, like query -> exit 6.
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
        .args(["schema", "db", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(6));
    assert_eq!(error_envelope(&out)["error"]["code"], "CONNECTION_FAILED");
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

// ---------------------------------------------------------------------------
// nyet doctor (SQLite / config-level, no Docker)
// ---------------------------------------------------------------------------

/// The default format is table (doctor is the human-facing command): the checks
/// render on stdout, the envelope on stderr — and SQLite is honestly reported as
/// having no roles/server/transport (`na`), never a faked pass (UX-7). Exit 0.
#[cfg(unix)]
#[test]
fn doctor_sqlite_is_honest_and_exits_0() {
    use std::os::unix::fs::PermissionsExt;
    let (tmp, cfg) = sqlite_fixture("");
    fs::set_permissions(&cfg, fs::Permissions::from_mode(0o600)).unwrap();
    // Default format is table: checks on stdout, envelope (json line) on stderr.
    let out = nyet(tmp.path())
        .args(["doctor", "db", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let table = stdout(&out);
    assert!(
        table.contains("ok") && table.contains("connectivity"),
        "{table}"
    );
    assert!(
        table.contains("na") && table.contains("read_only_role"),
        "{table}"
    );
    let env: serde_json::Value =
        serde_json::from_str(stderr(&out).trim().lines().last().unwrap()).unwrap();
    assert_eq!(env["ok"], true);
    assert!(
        env.get("checks").is_none(),
        "table envelope carries no checks"
    );

    // json format: the whole envelope on stdout; every na/ok honesty pinned.
    let out = nyet(tmp.path())
        .args(["doctor", "db", "--format", "json", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["meta"]["connection"], "db");
    let checks = v["checks"].as_array().unwrap();
    let by = |name: &str| {
        checks
            .iter()
            .find(|c| c["name"] == name)
            .unwrap_or_else(|| panic!("no {name}: {v}"))
            .clone()
    };
    assert_eq!(by("connectivity")["status"], "ok");
    for name in ["transport_encrypted", "read_only_role", "not_superuser"] {
        assert_eq!(by(name)["status"], "na", "{name}");
        assert!(by(name).get("hint").is_none(), "na carries no hint: {name}");
    }
    assert_eq!(by("config_permissions")["status"], "ok");
}

/// Loose config permissions are a `warn` check (not a refusal); a probe/role
/// check does not apply to SQLite. Pins that a problem is exit 0, not a failure.
#[cfg(unix)]
#[test]
fn doctor_flags_loose_config_permissions_but_exits_0() {
    use std::os::unix::fs::PermissionsExt;
    let (tmp, cfg) = sqlite_fixture("");
    fs::set_permissions(&cfg, fs::Permissions::from_mode(0o644)).unwrap();
    let out = nyet(tmp.path())
        .args(["doctor", "db", "--format", "json", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
    let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
    let perms = v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "config_permissions")
        .unwrap();
    assert_eq!(perms["status"], "warn");
    // Actionable (Д10): the hint says how to fix it.
    assert!(
        perms["hint"].as_str().unwrap().contains("chmod 600"),
        "{perms}"
    );
}

/// A connection that cannot be opened is a `fail` CHECK with exit 0 — NOT
/// CONNECTION_FAILED / exit 6. Diagnosing a broken connection is doctor's job.
#[test]
fn doctor_connect_failure_is_a_fail_check_not_exit_6() {
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
        .args(["doctor", "db", "--format", "json", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
    let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
    assert_eq!(v["ok"], true);
    let conn = v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "connectivity")
        .unwrap();
    assert_eq!(conn["status"], "fail");
    assert!(conn["hint"].is_string(), "{conn}");
}

/// `nyet doctor` with no alias: config-file permissions + the connections
/// reachable from here. Exit 0.
#[test]
fn doctor_without_alias_lists_reachable_connections() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = write_config(tmp.path(), &two_conn_config(tmp.path()));
    let out = nyet(tmp.path())
        .args(["doctor", "--format", "json", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
    // No connection field in meta for the config-level run.
    assert!(v["meta"].get("connection").is_none(), "{v}");
    let checks = v["checks"].as_array().unwrap();
    let connections = checks.iter().find(|c| c["name"] == "connections").unwrap();
    // `local` is reachable from cwd, `prod` is scoped elsewhere.
    assert_eq!(connections["status"], "ok");
    let msg = connections["message"].as_str().unwrap();
    assert!(msg.contains("local") && !msg.contains("prod"), "{msg}");
    assert!(checks.iter().any(|c| c["name"] == "config_permissions"));
}

/// An unknown alias is still a config error (exit 3), like every other command.
#[test]
fn doctor_unknown_alias_is_exit_3() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = write_config(tmp.path(), &two_conn_config(tmp.path()));
    let out = nyet(tmp.path())
        .args(["doctor", "nope", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    // Default format is table for doctor, so the error envelope routes to stderr.
    assert_eq!(stdout(&out), "");
    let v: serde_json::Value =
        serde_json::from_str(stderr(&out).trim().lines().last().unwrap()).unwrap();
    assert_eq!(v["error"]["code"], "CONFIG_INVALID");
}

// ---------------------------------------------------------------------------
// nyet agent-setup (local generation — no db, no network)
// ---------------------------------------------------------------------------

/// Assert the text is a valid SKILL.md skeleton: a frontmatter fence with
/// non-empty name/description, and the teaching body.
fn assert_valid_skill(text: &str) {
    assert!(
        text.starts_with("---\n"),
        "must open with a frontmatter fence"
    );
    let (frontmatter, body) = text[4..].split_once("\n---\n").expect("closing fence");
    assert!(
        frontmatter.lines().any(|l| l.trim() == "name: nyet"),
        "frontmatter: {frontmatter}"
    );
    assert!(
        frontmatter
            .lines()
            .any(|l| l.starts_with("description:") && l.trim().len() > "description:".len()),
        "frontmatter: {frontmatter}"
    );
    // Body teaches the commands, the envelope and the refusal mechanics, and
    // tells the agent to pass --format json (the default depends on the config).
    for marker in [
        "nyet query",
        "nyet schema",
        "5  query refused",
        "WRITE_OPERATION",
        "hint",
        "--format json",
    ] {
        assert!(body.contains(marker), "body missing {marker}");
    }
}

/// No config: agent-setup still emits a full instruction (exit 0) plus a hint
/// to set one up — its value is teaching the agent before setup. Markdown on
/// stdout, envelope on stderr.
#[test]
fn agent_setup_without_config_still_emits_instruction() {
    let tmp = tempfile::tempdir().unwrap();
    let out = nyet(tmp.path())
        .args(["agent-setup", "--config", "/no/such/config.toml"])
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let md = stdout(&out);
    assert_valid_skill(&md);
    assert!(md.contains("No nyet config was found"), "{md}");
    // Envelope routes to stderr (markdown is a data format).
    assert!(stderr(&out)
        .trim()
        .lines()
        .last()
        .unwrap()
        .contains(r#"{"v":1,"ok":true}"#));
}

/// With a real config, the dynamic section names the connections reachable from
/// cwd (consistent with `nyet list`) and a concrete example uses a real alias.
#[test]
fn agent_setup_lists_reachable_connections() {
    let (tmp, cfg) = sqlite_fixture("");
    let out = nyet(tmp.path())
        .args(["agent-setup", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let md = stdout(&out);
    assert_valid_skill(&md);
    let section = md.split("## Your connections").nth(1).unwrap();
    assert!(section.contains("db  sqlite"), "{section}");
    assert!(
        section.contains("nyet query db \"SELECT 1\" --format json"),
        "{section}"
    );
    // Only aliases + engines are advertised — never the file path / url.
    assert!(
        !md.contains("fixture.db"),
        "path leaked into the skill: {md}"
    );
}

/// `--format json` wraps the whole SKILL.md in the envelope's `skill` field on
/// stdout; the markdown (newlines, quotes) round-trips through JSON escaping.
#[test]
fn agent_setup_json_wraps_the_skill_in_the_envelope() {
    let (tmp, cfg) = sqlite_fixture("");
    let out = nyet(tmp.path())
        .args(["agent-setup", "--format", "json", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
    assert_eq!(v["v"], 1);
    assert_eq!(v["ok"], true);
    // The escaping is proven by the parse succeeding and the string coming back
    // with its real newlines and quotes intact.
    let skill = v["skill"].as_str().unwrap();
    assert_valid_skill(skill);
    assert!(skill.contains('\n') && skill.contains('"'));
    assert!(skill.contains("db  sqlite"));
}

/// A space-containing alias (a valid TOML quoted key) is accepted as one CLI
/// positional — so the shell-quoted example the skill generates really works.
#[test]
fn query_accepts_an_alias_containing_a_space() {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("fixture.db");
    make_db(&db);
    let cfg = write_config(
        tmp.path(),
        &format!(
            "[connections.\"prod db\"]\nengine = \"sqlite\"\npath = \"{}\"\n\
             allowed_dirs = [\"{}\"]\n",
            db.display(),
            tmp.path().display()
        ),
    );
    // Command::args passes "prod db" as a single argument (no shell splitting),
    // exactly what `nyet query 'prod db' ...` yields after the shell.
    let out = nyet(tmp.path())
        .args([
            "query",
            "prod db",
            "SELECT count(*) AS n FROM users",
            "--format",
            "json",
            "--config",
        ])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let v = success_envelope(&stdout(&out));
    assert_eq!(v["rows"], serde_json::json!([{"n": 3}]));
}

/// A leading-hyphen alias parses as an option unless it follows `--`; the skill
/// generates exactly that form, so verify clap honors `--` end-of-options.
#[test]
fn query_accepts_a_leading_hyphen_alias_after_end_of_options() {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("fixture.db");
    make_db(&db);
    let cfg = write_config(
        tmp.path(),
        &format!(
            "[connections.\"--weird\"]\nengine = \"sqlite\"\npath = \"{}\"\n\
             allowed_dirs = [\"{}\"]\n",
            db.display(),
            tmp.path().display()
        ),
    );
    // `--config` (global) before `--`; after `--` clap reads "--weird" as the
    // alias positional instead of an option.
    let out = nyet(tmp.path())
        .args(["query", "--format", "json", "--config"])
        .arg(&cfg)
        .args(["--", "--weird", "SELECT count(*) AS n FROM users"])
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let v = success_envelope(&stdout(&out));
    assert_eq!(v["rows"], serde_json::json!([{"n": 3}]));
}

// ---------------------------------------------------------------------------
// Audit log (UX-8): every database-touching command leaves a jsonl record;
// fail-closed when it cannot be written; opt-out via [audit] enabled = false.
// ---------------------------------------------------------------------------

/// The default audit-log location under a test HOME.
fn audit_file(home: &Path) -> std::path::PathBuf {
    home.join(".local/share/nyet/audit.jsonl")
}

/// The single audit record (fails if there is not exactly one line).
fn one_audit_record(home: &Path) -> serde_json::Value {
    let text = fs::read_to_string(audit_file(home)).expect("audit file must exist");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 1, "expected one audit line, got: {text}");
    serde_json::from_str(lines[0]).expect("audit line must be valid JSON")
}

#[test]
fn audit_records_a_successful_query() {
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
    // The result still reached the agent, unchanged.
    assert!(stdout(&out).contains(r#""rows":[{"id":1"#));
    // ...and a matching audit record was written first.
    let rec = one_audit_record(tmp.path());
    assert_eq!(rec["audit_v"], 1);
    assert_eq!(rec["command"], "query");
    assert_eq!(rec["alias"], "db");
    assert_eq!(rec["engine"], "sqlite");
    assert_eq!(rec["verdict"], "ok");
    assert_eq!(rec["exit_code"], 0);
    assert_eq!(rec["row_count"], 3);
    assert_eq!(rec["sql"], "SELECT id, email FROM users ORDER BY id");
    // ISO 8601 UTC timestamp — pin the shape, not the (flapping) value.
    let ts = rec["ts"].as_str().unwrap();
    assert!(
        ts.ends_with('Z') && ts.contains('T') && ts.len() >= 20,
        "ts: {ts}"
    );
    // No response body unless log_responses is on; no credentials anywhere.
    assert!(rec.get("response").is_none());
    let raw = fs::read_to_string(audit_file(tmp.path())).unwrap();
    assert!(!raw.contains("password") && !raw.contains("://"));
}

#[test]
fn audit_records_a_validator_refusal_with_reason() {
    let (tmp, cfg) = sqlite_fixture("");
    let out = nyet(tmp.path())
        .args(["query", "db", "DELETE FROM users", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(5));
    let rec = one_audit_record(tmp.path());
    assert_eq!(rec["command"], "query");
    assert_eq!(rec["verdict"], "refused");
    assert_eq!(rec["reason"], "WRITE_OPERATION");
    assert_eq!(rec["exit_code"], 5);
    assert_eq!(rec["sql"], "DELETE FROM users");
}

#[test]
fn audit_records_schema_and_explain() {
    let (tmp, cfg) = sqlite_fixture("");
    nyet(tmp.path())
        .args(["schema", "db", "users", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    nyet(tmp.path())
        .args(["explain", "db", "SELECT * FROM users", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    let text = fs::read_to_string(audit_file(tmp.path())).unwrap();
    let recs: Vec<serde_json::Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(recs.len(), 2);
    assert_eq!(recs[0]["command"], "schema");
    assert_eq!(recs[0]["table"], "users");
    assert_eq!(recs[0]["verdict"], "ok");
    assert_eq!(recs[1]["command"], "explain");
    assert_eq!(recs[1]["sql"], "SELECT * FROM users");
}

#[test]
fn audit_disabled_writes_nothing() {
    let (tmp, cfg) = sqlite_fixture("[audit]\nenabled = false\n");
    let out = nyet(tmp.path())
        .args(["query", "db", "SELECT 1 AS n", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(stdout(&out).contains(r#""rows":[{"n":1}]"#));
    assert!(
        !audit_file(tmp.path()).exists(),
        "no audit file when disabled"
    );
}

#[test]
fn audit_log_responses_includes_the_rows_the_agent_saw() {
    let (tmp, cfg) = sqlite_fixture("[audit]\nlog_responses = true\n");
    nyet(tmp.path())
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
    let rec = one_audit_record(tmp.path());
    // The response carries exactly the rows the agent received, in column order.
    assert_eq!(
        rec["response"],
        serde_json::json!([
            {"id": 1, "email": "a@b.c"},
            {"id": 2, "email": "d@e.f"},
            {"id": 3, "email": null}
        ])
    );
}

/// Fail-closed (UX-8, UX-1): if the audit record cannot be written, the query
/// result is NOT released — the agent gets AUDIT_FAILED (exit 1) and no rows.
#[test]
fn audit_write_failure_is_fail_closed_and_withholds_the_result() {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("fixture.db");
    make_db(&db);
    // A regular file stands where a directory would need to be, so mkdir of the
    // audit path's parent fails deterministically (ENOTDIR).
    let blocker = tmp.path().join("blocker");
    fs::write(&blocker, "x").unwrap();
    let audit_path = blocker.join("sub/audit.jsonl");
    let cfg = write_config(
        tmp.path(),
        &format!(
            "[audit]\npath = \"{}\"\n[connections.db]\nengine = \"sqlite\"\npath = \"{}\"\n\
             allowed_dirs = [\"{}\"]\n",
            audit_path.display(),
            db.display(),
            tmp.path().display()
        ),
    );
    let out = nyet(tmp.path())
        .args(["query", "db", "SELECT id, email FROM users", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let v = error_envelope(&out);
    assert_eq!(v["error"]["code"], "AUDIT_FAILED");
    assert!(v["error"]["hint"]
        .as_str()
        .unwrap()
        .contains("enabled = false"));
    // The data the agent must NOT have received.
    assert!(
        !stdout(&out).contains("a@b.c"),
        "result leaked despite audit failure"
    );
}

#[test]
fn audit_env_var_in_path_is_config_error() {
    let (tmp, cfg) = sqlite_fixture("[audit]\npath = \"${LOGDIR}/audit.jsonl\"\n");
    let out = nyet(tmp.path())
        .args(["query", "db", "SELECT 1", "--config"])
        .arg(&cfg)
        .env("LOGDIR", "/tmp/agent-owned")
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    let v = error_envelope(&out);
    assert_eq!(v["error"]["code"], "CONFIG_INVALID");
}

/// Cross-PROCESS concurrency: two nyet processes append large (>4 KiB) records
/// to the same audit file at once (log_responses on, a big blob row). The
/// advisory lock must keep both lines whole and valid.
#[test]
fn audit_is_safe_across_concurrent_processes() {
    let (tmp, cfg) = sqlite_fixture("[audit]\nlog_responses = true\n");
    let spawn = || {
        nyet(tmp.path())
            .args([
                "query",
                "db",
                "SELECT hex(randomblob(4096)) AS blob",
                "--config",
            ])
            .arg(&cfg)
            .current_dir(tmp.path())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap()
    };
    let a = spawn();
    let b = spawn();
    assert!(a.wait_with_output().unwrap().status.success());
    assert!(b.wait_with_output().unwrap().status.success());
    let text = fs::read_to_string(audit_file(tmp.path())).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "both processes must have logged");
    for l in &lines {
        let v: serde_json::Value = serde_json::from_str(l)
            .unwrap_or_else(|_| panic!("garbled line: {}", &l[..60.min(l.len())]));
        // 4096 bytes -> 8192 hex chars: the record is well past 4 KiB.
        assert_eq!(v["response"][0]["blob"].as_str().unwrap().len(), 8192);
    }
}

/// An existing audit log with group/other bits leaks the agent's SQL to other
/// local users — warn on stderr like the config file (warn, never chmod).
#[cfg(unix)]
#[test]
fn audit_warns_on_a_loose_existing_log_file() {
    use std::os::unix::fs::PermissionsExt;
    let (tmp, cfg) = sqlite_fixture("");
    let logf = audit_file(tmp.path());
    fs::create_dir_all(logf.parent().unwrap()).unwrap();
    fs::write(&logf, "").unwrap();
    fs::set_permissions(&logf, fs::Permissions::from_mode(0o644)).unwrap();
    let out = nyet(tmp.path())
        .args(["query", "db", "SELECT 1 AS n", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("audit log") && stderr(&out).contains("chmod"),
        "expected a loose-permissions warning: {}",
        stderr(&out)
    );
}

// ---------------------------------------------------------------------------
// PII policy (step PII-1): net A refuses by name before execution, net B by the
// driver's column provenance after it, and a connection with a policy never
// receives the raw database error text.
// ---------------------------------------------------------------------------

/// The one cell value that must never appear in either stream.
const PII_VALUE: &str = "alice@example.com";

/// Fixture: `users` (with a protected `email`), an unprotected `orders`, and a
/// VIEW that renames `users.email` — the case only net B can catch.
/// `pii_section` is appended after the connection block (TOML ordering).
fn pii_fixture(pii_section: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("pii.db");
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    rt.block_on(async {
        use sqlx::ConnectOptions;
        let mut conn = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&db)
            .create_if_missing(true)
            .connect()
            .await
            .unwrap();
        for sql in [
            "CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, created_at TEXT)".to_string(),
            "CREATE TABLE orders (id INTEGER PRIMARY KEY, uid INTEGER, amount INTEGER)".to_string(),
            "CREATE TABLE dict (id INTEGER, email TEXT, note TEXT)".to_string(),
            // a user table that only SHARES A NAME with MariaDB's histogram
            // catalog — on sqlite it is an ordinary table (finding 10)
            "CREATE TABLE column_stats (id INTEGER, n INTEGER)".to_string(),
            "CREATE VIEW v_users AS SELECT id, email AS contact FROM users".to_string(),
            // A SECOND renaming view, so a rule can name a column the driver
            // never reports (v_dict.work_mail -> dict.email): the shape that
            // proved net A's promise cannot be kept by POSITION.
            "CREATE VIEW v_dict AS SELECT id, email AS work_mail FROM dict".to_string(),
            format!("INSERT INTO users VALUES (1, '{PII_VALUE}', '2020-01-01')"),
            // A NULL protected value: masking must not leave it as null (that
            // would answer "is this row's value set?" for every row).
            "INSERT INTO users VALUES (2, NULL, '2020-02-02')".to_string(),
            format!("INSERT INTO dict VALUES (1, '{PII_VALUE}', 'x')"),
            "INSERT INTO orders VALUES (1, 1, 42)".to_string(),
            "INSERT INTO column_stats VALUES (1, 7)".to_string(),
        ] {
            sqlx::query(sqlx::AssertSqlSafe(sql))
                .execute(&mut conn)
                .await
                .unwrap();
        }
        sqlx::Connection::close(conn).await.unwrap();
    });
    let cfg = write_config(
        tmp.path(),
        &format!(
            "[connections.db]\nengine = \"sqlite\"\npath = \"{}\"\n\
             allowed_dirs = [\"{}\"]\n{pii_section}",
            db.display(),
            tmp.path().display()
        ),
    );
    (tmp, cfg)
}

const PII_SECTION: &str = "[connections.db.pii]\ncolumns = [\"users.email\"]\n";

/// The same policy, one sanction over (`mode = "mask"`).
const PII_MASK_SECTION: &str =
    "[connections.db.pii]\ncolumns = [\"users.email\"]\nmode = \"mask\"\n";

fn run_query(tmp: &Path, cfg: &Path, sql: &str) -> Output {
    nyet(tmp)
        .args(["query", "db", sql, "--config"])
        .arg(cfg)
        .current_dir(tmp)
        .output()
        .unwrap()
}

/// Neither stream may ever carry the protected value.
fn assert_no_pii_leak(out: &Output, sql: &str) {
    assert!(!stdout(out).contains(PII_VALUE), "{sql}: leaked to stdout");
    assert!(!stderr(out).contains(PII_VALUE), "{sql}: leaked to stderr");
}

#[test]
fn pii_net_a_refuses_before_execution() {
    let (tmp, cfg) = pii_fixture(PII_SECTION);
    for sql in [
        "SELECT email FROM users",
        "SELECT u.email FROM users u",
        "SELECT substr(email, 1, 3) FROM users",
        "SELECT * FROM users",
        "SELECT count(*) FROM users WHERE email LIKE 'a%'",
        "SELECT id FROM users ORDER BY email",
        // finding 3: USING / NATURAL name the join column outside the Expr
        // tree — both were a working join oracle over the protected value.
        "SELECT count(*) AS n FROM users JOIN dict USING (email)",
        "SELECT count(*) AS n FROM users NATURAL JOIN dict",
        // round 2, finding B: a parenthesised join hides its constraint one
        // level down, and the agent can bring its own dictionary — this is a
        // full equality oracle over the protected value.
        "SELECT count(*) AS n FROM (users JOIN dict USING (email))",
        "SELECT count(*) AS n FROM (users NATURAL JOIN dict)",
        "SELECT count(*) AS n FROM (users NATURAL JOIN (SELECT 'x' AS email) d)",
        "SELECT count(*) AS n FROM orders o JOIN (users JOIN dict USING (email)) x ON 1=1",
    ] {
        let out = run_query(tmp.path(), &cfg, sql);
        assert_eq!(out.status.code(), Some(5), "{sql}: {}", stderr(&out));
        let v = error_envelope(&out);
        assert_eq!(v["error"]["code"], "NYET", "{sql}");
        assert_eq!(v["error"]["reason"], "PII_COLUMN", "{sql}");
        let hint = v["error"]["hint"].as_str().unwrap();
        assert!(hint.contains("no CLI flag"), "{sql}: {hint}");
        assert_no_pii_leak(&out, sql);
    }
}

#[test]
fn pii_net_b_catches_a_renaming_view() {
    // Net A sees only `v_users.contact` — no rule mentions it — so the query
    // runs; SQLite reports the column's true origin (users.email) and net B
    // refuses before a single row is formatted.
    let (tmp, cfg) = pii_fixture(PII_SECTION);
    let out = run_query(tmp.path(), &cfg, "SELECT contact FROM v_users");
    assert_eq!(out.status.code(), Some(5), "{}", stderr(&out));
    let v = error_envelope(&out);
    assert_eq!(v["error"]["reason"], "PII_COLUMN");
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("users.email"),
        "{v}"
    );
    assert_no_pii_leak(&out, "SELECT contact FROM v_users");
    // The unmarked column of the same view is fine.
    let out = run_query(tmp.path(), &cfg, "SELECT id FROM v_users");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
}

#[test]
fn pii_leaves_unmarked_reads_working() {
    // Otherwise the feature is just a wall (UX-2/UX-1 balance).
    let (tmp, cfg) = pii_fixture(PII_SECTION);
    for sql in [
        "SELECT count(*) AS n FROM users",
        "SELECT id, created_at FROM users",
        "SELECT * FROM orders",
        "SELECT id, amount FROM orders WHERE amount > 10",
        // finding 9: the wildcard's own source has no rules, so nothing
        // protected can come back — these used to be refused with a message
        // that was simply untrue.
        "SELECT * FROM orders WHERE uid IN (SELECT id FROM users)",
        "SELECT o.* FROM orders o JOIN users u ON u.id = o.uid",
        // finding 10: an ordinary user table that shares its name with
        // MariaDB's histogram catalog is not a catalog on sqlite.
        "SELECT n FROM column_stats",
        // round 2, finding D: a subquery inside FROM is not the wildcard's source
        "SELECT * FROM (SELECT id FROM users) t",
        // round 2, finding E: a qualified prefix that provably names an unruled
        // source settles ownership — the same proof `o.*` already uses
        "SELECT o.uid FROM orders o JOIN users u ON u.id = o.uid",
        // round 2, finding F: an ALIAS spelling a protected table name is not
        // that table
        "SELECT amount FROM orders AS users",
        "SELECT * FROM orders AS users",
    ] {
        let out = run_query(tmp.path(), &cfg, sql);
        assert_eq!(out.status.code(), Some(0), "{sql}: {}", stderr(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert_eq!(v["ok"], true, "{sql}");
        assert_no_pii_leak(&out, sql);
    }
}

#[test]
fn without_a_pii_section_nothing_changes() {
    // UX-5: an existing config keeps its exact behavior, value and all.
    let (tmp, cfg) = pii_fixture("");
    let out = run_query(tmp.path(), &cfg, "SELECT email FROM users");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(stdout(&out).contains(PII_VALUE), "{}", stdout(&out));
    // ...including the verbatim database error text.
    let out = run_query(tmp.path(), &cfg, "SELECT nosuchcol FROM orders");
    assert_eq!(out.status.code(), Some(7));
    let v = error_envelope(&out);
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("nosuchcol"),
        "{v}"
    );
}

#[test]
fn pii_withholds_the_database_error_text() {
    // A database error can quote the offending CELL VALUE (PostgreSQL:
    // `invalid input syntax for type integer: "..."`), which is an exfiltration
    // channel one cell per query. With a PII policy the whole message is
    // withheld — no pattern filtering, that would be theatre (UX-7).
    let (tmp, cfg) = pii_fixture(PII_SECTION);
    let out = run_query(tmp.path(), &cfg, "SELECT nosuchcol FROM orders");
    assert_eq!(out.status.code(), Some(7), "{}", stderr(&out));
    let v = error_envelope(&out);
    assert_eq!(v["error"]["code"], "DB_ERROR");
    let message = v["error"]["message"].as_str().unwrap();
    assert!(message.contains("withheld"), "{message}");
    assert!(!message.contains("nosuchcol"), "{message}");
    assert!(
        v["error"]["hint"].as_str().unwrap().contains("nyet schema"),
        "{v}"
    );
}

#[test]
fn a_malformed_pii_rule_is_exit_3() {
    for (section, marker) in [
        (
            "[connections.db.pii]\ncolumns = [\"email\"]\n",
            "table.column",
        ),
        (
            "[connections.db.pii]\ncolumns = [\"${PII_RULE}\"]\n",
            "literal",
        ),
    ] {
        let (tmp, cfg) = pii_fixture(section);
        let out = nyet(tmp.path())
            .args(["query", "db", "SELECT 1", "--config"])
            .arg(&cfg)
            .env("PII_RULE", "users.email")
            .current_dir(tmp.path())
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(3), "{section}: {}", stderr(&out));
        let v = error_envelope(&out);
        assert_eq!(v["error"]["code"], "CONFIG_INVALID");
        let text = format!("{} {}", v["error"]["message"], v["error"]["hint"]);
        assert!(text.contains(marker), "{section}: {text}");
    }
}

#[test]
fn pii_refusals_are_audited_without_the_data() {
    // The refusal IS logged (the human sees what the agent tried), and the log
    // can never hold rows the agent did not get: both nets run before the
    // `response` payload is built, so a refused query has none.
    let (tmp, cfg) = pii_fixture(&format!("{PII_SECTION}[audit]\nlog_responses = true\n"));
    // Net A refusal.
    let out = run_query(tmp.path(), &cfg, "SELECT email FROM users");
    assert_eq!(out.status.code(), Some(5), "{}", stderr(&out));
    // Net B refusal, on the same log.
    let out = run_query(tmp.path(), &cfg, "SELECT contact FROM v_users");
    assert_eq!(out.status.code(), Some(5), "{}", stderr(&out));
    let text = fs::read_to_string(audit_file(tmp.path())).expect("audit file must exist");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "{text}");
    for line in &lines {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["verdict"], "refused", "{v}");
        assert_eq!(v["reason"], "PII_COLUMN", "{v}");
        assert_eq!(v["exit_code"], 5, "{v}");
        // The raw SQL stays (forensics for the human, file mode 0600), the data
        // never appears.
        assert!(v["sql"].is_string(), "{v}");
        assert!(v.get("response").is_none(), "{v}");
    }
    assert!(!text.contains(PII_VALUE), "the audit log leaked the value");
}

/// The view limitation, pinned in BOTH directions so it cannot drift silently
/// (finding 1). Net B judges the origin the driver reports; an expression
/// carries no origin at all, so wrapping a view column defeats it exactly the
/// way the bare column already defeats it on PostgreSQL and MySQL. The
/// documented, enforceable answer is to list the view's own columns.
#[test]
fn pii_view_limitation_is_pinned_in_both_directions() {
    let (tmp, cfg) = pii_fixture(PII_SECTION);
    // Unlisted view + a computed column: nyet does NOT catch this. Pinned so a
    // change (in either direction) shows up as a failing test, not as a
    // silently changed guarantee.
    for sql in [
        "SELECT contact || '' AS c FROM v_users",
        "SELECT substr(contact, 1, 50) AS c FROM v_users",
        "SELECT count(*) AS n FROM v_users WHERE contact LIKE 'a%'",
    ] {
        let out = run_query(tmp.path(), &cfg, sql);
        assert_eq!(out.status.code(), Some(0), "{sql}: {}", stderr(&out));
    }
    // Listing the view closes all three: net A now knows `v_users.contact`.
    let (tmp, cfg) =
        pii_fixture("[connections.db.pii]\ncolumns = [\"users.email\", \"v_users.contact\"]\n");
    for sql in [
        "SELECT contact FROM v_users",
        "SELECT contact || '' AS c FROM v_users",
        "SELECT substr(contact, 1, 50) AS c FROM v_users",
        "SELECT count(*) AS n FROM v_users WHERE contact LIKE 'a%'",
    ] {
        let out = run_query(tmp.path(), &cfg, sql);
        assert_eq!(out.status.code(), Some(5), "{sql}: {}", stdout(&out));
        let v = error_envelope(&out);
        assert_eq!(v["error"]["reason"], "PII_COLUMN", "{sql}");
        assert_no_pii_leak(&out, sql);
    }
}

/// `mode = "mask"`: the plain projection comes back with the cells replaced —
/// NULL included — plus the warning that says so. Nothing about the real value
/// (not its type, not its length, not whether it was set) survives.
#[test]
fn pii_mask_redacts_the_values_and_warns() {
    let (tmp, cfg) = pii_fixture(PII_MASK_SECTION);
    let out = run_query(tmp.path(), &cfg, "SELECT id, email FROM users");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
    assert_eq!(v["ok"], true, "{v}");
    let rows = v["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 2, "{v}");
    for row in rows {
        // The unprotected column is untouched, the protected one is gone —
        // and the NULL row reads exactly like the non-NULL one.
        assert!(row["id"].is_number(), "{row}");
        assert_eq!(row["email"], "[REDACTED]", "{row}");
    }
    let warnings = v["warnings"].as_array().unwrap();
    let masked = warnings
        .iter()
        .find(|w| w["code"] == "PII_MASKED")
        .unwrap_or_else(|| panic!("no PII_MASKED warning: {v}"));
    let message = masked["message"].as_str().unwrap();
    assert!(message.contains("'email'"), "{message}");
    assert!(message.contains("[REDACTED]"), "{message}");
    assert_no_pii_leak(&out, "SELECT id, email FROM users");

    // Net B masks ONLY what net A sanctioned: a view column no rule names is
    // refused, exactly as under `deny` (see
    // `pii_mask_never_masks_what_net_a_did_not_sanction`).
    let out = run_query(tmp.path(), &cfg, "SELECT contact FROM v_users");
    assert_eq!(out.status.code(), Some(5), "{}", stdout(&out));
    assert_no_pii_leak(&out, "SELECT contact FROM v_users");
}

/// Net A's exemption is a PROMISE that net B will redact the column, and a
/// promise nyet cannot keep must refuse (`PII_UNPROVABLE`) — never hand the
/// value over. Two ways the promise breaks, both agent-reachable, both found in
/// review:
///
/// 1. the README's own recipe for views (`columns = ["v_users.contact"]`): net A
///    protects the VIEW's column, SQLite reports the BASE table's
///    (`users.email`), which no rule names — so nothing was masked. Under `deny`
///    this very query is refused; masking must not turn a refusal into a full
///    disclosure (UX-1);
/// 2. a CTE shadowing the protected table's name: the scope is active, the
///    projection is exempted, and the value is a computed expression with no
///    provenance at all.
#[test]
fn pii_mask_refuses_when_it_cannot_keep_its_promise() {
    let (tmp, cfg) =
        pii_fixture("[connections.db.pii]\ncolumns = [\"v_users.contact\"]\nmode = \"mask\"\n");
    let sql = "SELECT contact FROM v_users";
    let out = run_query(tmp.path(), &cfg, sql);
    assert_eq!(out.status.code(), Some(5), "{sql}: {}", stdout(&out));
    let v = error_envelope(&out);
    assert_eq!(v["error"]["reason"], "PII_UNPROVABLE", "{v}");
    assert_no_pii_leak(&out, sql);
    // The same policy under the default mode refuses too — the mode must not be
    // the difference between a refusal and the plain value.
    let (tmp, cfg) = pii_fixture("[connections.db.pii]\ncolumns = [\"v_users.contact\"]\n");
    let out = run_query(tmp.path(), &cfg, sql);
    assert_eq!(out.status.code(), Some(5), "{sql}: {}", stdout(&out));
    assert_no_pii_leak(&out, sql);

    // Listing BOTH pairs is the working configuration: the base-table rule is
    // what the driver's provenance actually reports, so the value is masked.
    let (tmp, cfg) = pii_fixture(
        "[connections.db.pii]\ncolumns = [\"users.email\", \"v_users.contact\"]\nmode = \"mask\"\n",
    );
    let out = run_query(tmp.path(), &cfg, sql);
    assert_eq!(out.status.code(), Some(0), "{sql}: {}", stdout(&out));
    let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
    assert_eq!(v["rows"][0]["contact"], "[REDACTED]", "{v}");
    assert_no_pii_leak(&out, sql);

    // A computed value carries no provenance, so the promise cannot be kept —
    // even when the value is the agent's own literal.
    let (tmp, cfg) = pii_fixture(PII_MASK_SECTION);
    let sql = "WITH users AS (SELECT 'secret' AS email) SELECT email FROM users";
    let out = run_query(tmp.path(), &cfg, sql);
    assert_eq!(out.status.code(), Some(5), "{sql}: {}", stdout(&out));
    let v = error_envelope(&out);
    assert_eq!(v["error"]["reason"], "PII_UNPROVABLE", "{v}");
    assert!(!stdout(&out).contains("secret"), "{}", stdout(&out));
}

/// A wildcard expands into N result columns, so nothing in the SELECT list to
/// its right sits where net A thinks it does — the promise net B checks would be
/// kept by the WRONG column, and the one net A actually let through goes out
/// raw. Found in review; reproduced with two renaming views, where net B masks
/// the wildcard's column (its origin is a protected base column) while the
/// exempted one carries a rule the driver never reports.
#[test]
fn pii_mask_refuses_a_wildcard_beside_a_masked_column() {
    let (tmp, cfg) = pii_fixture(
        "[connections.db.pii]\ncolumns = [\"users.email\", \"v_dict.work_mail\"]\nmode = \"mask\"\n",
    );
    for sql in [
        "SELECT v_users.*, d.work_mail FROM v_users, v_dict d",
        "SELECT d.work_mail, v_users.* FROM v_users, v_dict d",
        "SELECT o.*, d.work_mail FROM orders o, v_dict d",
    ] {
        let out = run_query(tmp.path(), &cfg, sql);
        assert_eq!(out.status.code(), Some(5), "{sql}: {}", stdout(&out));
        let v = error_envelope(&out);
        assert_eq!(v["error"]["code"], "NYET", "{sql}");
        assert_no_pii_leak(&out, sql);
    }
    // Naming the columns instead of the wildcard is the way through, and the
    // protected one comes back masked (the hint says so).
    let out = run_query(tmp.path(), &cfg, "SELECT id, email FROM users");
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
    let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
    assert_eq!(v["rows"][0]["email"], "[REDACTED]", "{v}");
    assert_no_pii_leak(&out, "SELECT id, email FROM users");
}

/// A positional sort key has three spellings the engines all read as an ordinal
/// (`1`, `+1`, `(1)` — measured on SQLite and MySQL 8.4), and only the first was
/// checked: the other two sorted by the REAL value while every cell came back
/// redacted.
#[test]
fn pii_mask_refuses_every_positional_spelling() {
    let (tmp, cfg) = pii_fixture(PII_MASK_SECTION);
    for sql in [
        "SELECT email, id FROM users ORDER BY 1",
        "SELECT email, id FROM users ORDER BY +1",
        "SELECT email, id FROM users ORDER BY (1)",
        "SELECT email, id FROM users ORDER BY ((+1))",
        "SELECT email FROM users GROUP BY +1",
        "SELECT email FROM users GROUP BY (1)",
        // Spellings a fuzz of 47 forms found the engines ALSO read as an
        // ordinal (hex literals — PostgreSQL 16 added them —, a double
        // negation, a COLLATE suffix, a digit separator). Enumerating them was
        // the wrong model: what is refused now is any sort key that is not a
        // plain column NAME.
        "SELECT email, id FROM users ORDER BY 0x1",
        "SELECT email, id FROM users ORDER BY -(-1)",
        "SELECT email, id FROM users ORDER BY 1 COLLATE NOCASE",
        "SELECT email, id FROM users ORDER BY (1) COLLATE BINARY",
        "SELECT email FROM users GROUP BY 0x1",
        "SELECT email, id FROM users ORDER BY abs(1)",
        "SELECT email, id FROM users ORDER BY 1 + 0",
        // ...and the position of an UNPROTECTED column is refused too: nyet no
        // longer models which spellings each planner folds to an ordinal.
        "SELECT id, email FROM users ORDER BY 1",
        "SELECT id, email FROM users ORDER BY 0x1",
    ] {
        let out = run_query(tmp.path(), &cfg, sql);
        assert_eq!(out.status.code(), Some(5), "{sql}: {}", stdout(&out));
        let v = error_envelope(&out);
        assert_eq!(v["error"]["reason"], "PII_COLUMN", "{sql}");
        assert_no_pii_leak(&out, sql);
    }
    // Ordering by a column NAME is the shape that keeps working — protected
    // names are refused by name, everything else sorts as usual.
    for sql in [
        "SELECT id, email FROM users ORDER BY id",
        "SELECT id, email FROM users ORDER BY created_at DESC",
        "SELECT id, email FROM users u ORDER BY u.id",
        "SELECT id, email FROM users GROUP BY id",
    ] {
        let out = run_query(tmp.path(), &cfg, sql);
        assert_eq!(out.status.code(), Some(0), "{sql}: {}", stdout(&out));
    }
}

/// Net B must never mask a column net A did not sanction: it knows more than net
/// A does (SQLite resolves a view column to its base table), and a column that
/// only IT can see is one net A could not judge the ORDER BY / DISTINCT over —
/// which sorted and deduplicated by the real value. `deny` refuses these, so
/// `mask` must too.
#[test]
fn pii_mask_never_masks_what_net_a_did_not_sanction() {
    let (tmp, cfg) = pii_fixture(PII_MASK_SECTION);
    for sql in [
        "SELECT id, contact FROM v_users ORDER BY contact",
        "SELECT DISTINCT contact FROM v_users",
        "SELECT contact FROM v_users",
    ] {
        let out = run_query(tmp.path(), &cfg, sql);
        assert_eq!(out.status.code(), Some(5), "{sql}: {}", stdout(&out));
        let v = error_envelope(&out);
        assert_eq!(v["error"]["code"], "NYET", "{sql}");
        assert_no_pii_leak(&out, sql);
    }
    // Listing the view is the documented fix, and then net A sanctions it.
    let (tmp, cfg) = pii_fixture(
        "[connections.db.pii]\ncolumns = [\"users.email\", \"v_users.contact\"]\nmode = \"mask\"\n",
    );
    let out = run_query(tmp.path(), &cfg, "SELECT contact FROM v_users");
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
    let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
    assert_eq!(v["rows"][0]["contact"], "[REDACTED]", "{v}");
}

/// The mask relaxes the PROJECTION and nothing else: everything that could read
/// the real value back out — a filter, a sort, a grouping, a whole-row read, a
/// join oracle — keeps the deny-mode refusal, and the hint teaches the mask.
#[test]
fn pii_mask_still_refuses_every_oracle() {
    let (tmp, cfg) = pii_fixture(PII_MASK_SECTION);
    for sql in [
        "SELECT count(*) AS n FROM users WHERE email LIKE 'a%'",
        "SELECT email FROM users ORDER BY 1",
        "SELECT email FROM users ORDER BY email",
        "SELECT DISTINCT email FROM users",
        "SELECT email FROM users GROUP BY 1",
        "SELECT email AS x FROM users",
        "SELECT substr(email, 1, 3) AS x FROM users",
        "SELECT * FROM users",
        "SELECT u.* FROM users u",
        "SELECT count(*) AS n FROM users JOIN dict USING (email)",
        "SELECT count(*) AS n FROM users NATURAL JOIN dict",
        "SELECT count(*) AS n FROM (users JOIN dict USING (email))",
        "WITH x AS (SELECT email FROM users) SELECT count(*) AS n FROM x",
        "SELECT * FROM (SELECT email FROM users) t",
    ] {
        let out = run_query(tmp.path(), &cfg, sql);
        assert_eq!(out.status.code(), Some(5), "{sql}: {}", stdout(&out));
        let v = error_envelope(&out);
        assert_eq!(v["error"]["reason"], "PII_COLUMN", "{sql}");
        let hint = v["error"]["hint"].as_str().unwrap();
        assert!(hint.contains("[REDACTED]"), "{sql}: {hint}");
        assert!(hint.contains("no CLI flag"), "{sql}: {hint}");
        assert_no_pii_leak(&out, sql);
    }
    // ...and the very same statements are still refused under the default mode,
    // where the plain projection is refused too (UX-5: no config, no change).
    let (tmp, cfg) = pii_fixture(PII_SECTION);
    let out = run_query(tmp.path(), &cfg, "SELECT id, email FROM users");
    assert_eq!(out.status.code(), Some(5), "{}", stdout(&out));
}

/// `[pii]` marks the columns in `nyet schema` (both forms) so the agent never
/// spends a round trip discovering them by refusal (UX-2/UX-3).
#[test]
fn pii_columns_are_marked_in_schema() {
    for (section, mode) in [(PII_SECTION, "deny"), (PII_MASK_SECTION, "mask")] {
        let (tmp, cfg) = pii_fixture(section);
        let out = nyet(tmp.path())
            .args(["schema", "db", "users", "--config"])
            .arg(&cfg)
            .current_dir(tmp.path())
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(0), "{mode}: {}", stderr(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        let columns = v["schema"]["tables"][0]["columns"].as_array().unwrap();
        for column in columns {
            let want = if column["name"] == "email" {
                serde_json::Value::from(mode)
            } else {
                serde_json::Value::Null
            };
            assert_eq!(column["pii"], want, "{mode}: {column}");
        }
        // The human/table form carries it too.
        let out = nyet(tmp.path())
            .args(["schema", "db", "users", "--format", "table", "--config"])
            .arg(&cfg)
            .current_dir(tmp.path())
            .output()
            .unwrap();
        assert!(
            stdout(&out).contains(&format!("pii {mode}")),
            "{mode}: {}",
            stdout(&out)
        );
    }
    // No policy, no marking (and not a byte of extra output).
    let (tmp, cfg) = pii_fixture("");
    let out = nyet(tmp.path())
        .args(["schema", "db", "users", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert!(!stdout(&out).contains("pii"), "{}", stdout(&out));
}

/// The audit log holds exactly what the agent saw — masked. `sql` stays raw
/// (forensics for the human, file mode 0600), the cell value never appears.
#[test]
fn pii_mask_is_audited_without_the_data() {
    let (tmp, cfg) = pii_fixture(&format!(
        "{PII_MASK_SECTION}[audit]\nlog_responses = true\n"
    ));
    let out = run_query(tmp.path(), &cfg, "SELECT id, email FROM users");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let text = fs::read_to_string(audit_file(tmp.path())).expect("audit file must exist");
    let v: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
    assert_eq!(v["verdict"], "ok", "{v}");
    assert_eq!(v["warnings"][0], "PII_MASKED", "{v}");
    let rows = v["response"].as_array().unwrap();
    assert_eq!(rows.len(), 2, "{v}");
    for row in rows {
        assert_eq!(row["email"], "[REDACTED]", "{v}");
        assert!(row["id"].is_number(), "{v}");
    }
    assert!(!text.contains(PII_VALUE), "the audit log leaked the value");
}

/// `nyet doctor` is honest about what the policy is worth on SQLite: there is no
/// role to hide the columns from, so nyet is the only thing enforcing them — and
/// a connection without a `[pii]` section gets no such check at all (UX-4: an
/// `na` line on every ordinary connection is pure noise).
#[test]
fn pii_doctor_check_is_na_on_sqlite_and_absent_without_a_policy() {
    let doctor = |section: &str| {
        let (tmp, cfg) = pii_fixture(section);
        let out = nyet(tmp.path())
            .args(["doctor", "db", "--format", "json", "--config"])
            .arg(&cfg)
            .current_dir(tmp.path())
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        v["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "pii_columns")
            .cloned()
    };
    let check = doctor(PII_MASK_SECTION).expect("a policy must produce the check");
    assert_eq!(check["status"], "na", "{check}");
    assert!(
        check["message"].as_str().unwrap().contains("only thing"),
        "{check}"
    );
    assert!(doctor("").is_none(), "no policy, no check");
}

/// Net A is shared by `query` and `explain`, so a plan for a refused query is
/// refused too — pinned because `explain` returns no rows and therefore has no
/// net B of its own (finding 6).
#[test]
fn pii_explain_is_refused_like_the_query() {
    let (tmp, cfg) = pii_fixture(PII_SECTION);
    for sql in ["SELECT email FROM users", "SELECT * FROM users"] {
        let out = nyet(tmp.path())
            .args(["explain", "db", sql, "--config"])
            .arg(&cfg)
            .current_dir(tmp.path())
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(5), "{sql}: {}", stdout(&out));
        let v = error_envelope(&out);
        assert_eq!(v["error"]["reason"], "PII_COLUMN", "{sql}");
        assert_no_pii_leak(&out, sql);
    }
}

/// `nyet doctor` keeps the honest CONNECT message even on a PII connection —
/// symmetric with `engine_failure`, which passes `EngineError::Connect` through
/// verbatim too. A refused handshake happens before any row exists, and doctor
/// exists to tell the human why the connection is broken (round 2, finding H).
/// The write PROBE, which does run a statement, is redacted instead — unit
/// tested on `redact_diagnosis`, since provoking a probe detail needs a server.
#[test]
fn pii_doctor_keeps_the_connect_diagnosis_honest() {
    let tmp = tempfile::tempdir().unwrap();
    let broken = format!("{}/nosuchdir/x.db", tmp.path().display());
    for pii in ["", "[connections.db.pii]\ncolumns = [\"users.email\"]\n"] {
        let cfg = write_config(
            tmp.path(),
            &format!(
                "[connections.db]\nengine = \"sqlite\"\npath = \"{broken}\"\n\
                 allowed_dirs = [\"{}\"]\n{pii}",
                tmp.path().display()
            ),
        );
        let out = nyet(tmp.path())
            .args(["doctor", "db", "--format", "json", "--config"])
            .arg(&cfg)
            .current_dir(tmp.path())
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        assert!(
            stdout(&out).contains("nosuchdir"),
            "doctor must stay diagnostic: {}",
            stdout(&out)
        );
    }
}
