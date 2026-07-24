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
fn query_resolved_is_not_implemented_exit_1() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = write_config(tmp.path(), &two_conn_config(tmp.path()));
    let out = nyet(tmp.path())
        .args(["query", "local", "select 1", "--config"])
        .arg(&cfg)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let v = error_envelope(&out);
    assert_eq!(v["error"]["code"], "NOT_IMPLEMENTED");
}

#[test]
fn cli_usage_error_is_exit_2() {
    let tmp = tempfile::tempdir().unwrap();
    let out = nyet(tmp.path()).arg("frobnicate").output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let out = nyet(tmp.path()).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
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
