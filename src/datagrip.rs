//! `nyet import datagrip` — JetBrains data sources into config sections.
//!
//! Pure: XML text in, TOML text out. Finding the files is the cli layer's job
//! (D1), which keeps this testable without a JetBrains install.
//!
//! Two decisions shape everything here.
//!
//! **Passwords are not imported, and not because it is hard.** DataGrip keeps
//! them in its own KeePass store (`<secret-storage>master_key</secret-storage>`
//! in the XML is a pointer, not a value). nyet could learn that format — but a
//! tool whose whole pitch is "the agent does not get the secret even after
//! finding the config" has no business copying secrets into a config file. The
//! import emits a `{ keychain = ... }` reference and the `nyet secret-set`
//! line that fills it; the human runs that once.
//!
//! **`allowed_dirs` is emitted empty on purpose.** Which directories a
//! connection serves is knowledge only the human has — DataGrip does not
//! record it. Empty means denied everywhere (fail closed), so an unreviewed
//! import grants nothing; the alternative, guessing `["~"]`, would hand an
//! agent every production database the moment it ran the command.

use roxmltree::Document;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// One `<data-source>` from `dataSources.xml`, joined with what
/// `dataSources.local.xml` knows about it (the user name and the ssh config
/// live there, in the file JetBrains does not commit).
#[derive(Debug, Clone, PartialEq)]
pub struct Source {
    pub name: String,
    pub uuid: String,
    /// `<driver-ref>`, e.g. `postgresql`, `mongo.4`, `sqlite.xerial`.
    pub driver: String,
    /// `<jdbc-url>`, still carrying the `jdbc:` prefix.
    pub jdbc_url: String,
    pub user: Option<String>,
    /// `<ssh-properties>` → `<ssh-config-id>`, resolved against `sshConfigs.xml`.
    pub ssh_config_id: Option<String>,
}

/// The half of a data source that lives in `dataSources.local.xml`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Local {
    pub user: Option<String>,
    pub ssh_config_id: Option<String>,
}

/// An `<sshConfig>` entry: enough to write nyet's `[ssh] host`.
#[derive(Debug, Clone, PartialEq)]
pub struct SshConfig {
    pub host: String,
    pub port: Option<u16>,
    pub username: Option<String>,
}

/// What the import decided about one data source.
#[derive(Debug, Clone, PartialEq)]
pub enum Mapped {
    /// Renders into a `[connections.<alias>]` section.
    Ready(Connection),
    /// Named in the report, not in the config: an engine nyet does not speak,
    /// or a url it could not read.
    Skipped { name: String, reason: String },
}

/// A connection ready to be rendered. Deliberately strings: this is a config
/// generator, and `config::Connection` is the parser's shape, not this one's.
#[derive(Debug, Clone, PartialEq)]
pub struct Connection {
    pub alias: String,
    pub source_name: String,
    pub engine: &'static str,
    /// `url` for everything except sqlite, where nyet takes `path`.
    pub url: String,
    pub is_sqlite: bool,
    /// Emitted only when the source authenticates as somebody: a keychain
    /// reference for a database that needs no password is noise the human has
    /// to delete.
    pub wants_password: bool,
    pub ssh: Option<Tunnel>,
    /// Carried into the output as a comment: a rewrite the human should see
    /// rather than discover (ClickHouse jdbc → the HTTP interface).
    pub note: Option<String>,
}

/// nyet's `[connections.X.ssh]`, built from the bastion in `sshConfigs.xml`
/// plus the address the jdbc url points at (which, behind a tunnel, is the
/// address as seen FROM the bastion — exactly what `remote` means).
#[derive(Debug, Clone, PartialEq)]
pub struct Tunnel {
    pub host: String,
    pub remote: String,
}

/// Data sources in `dataSources.xml`. A malformed file yields an error; a
/// well-formed file missing the fields we need yields fewer sources, because
/// JetBrains writes plenty of shapes and a partial import beats a refusal.
pub fn parse_sources(xml: &str) -> Result<Vec<Source>, String> {
    let doc = Document::parse(xml).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for node in doc.descendants().filter(|n| n.has_tag_name("data-source")) {
        let (Some(name), Some(uuid)) = (node.attribute("name"), node.attribute("uuid")) else {
            continue;
        };
        let child_text = |tag: &str| {
            node.children()
                .find(|c| c.has_tag_name(tag))
                .and_then(|c| c.text())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
        };
        let Some(jdbc_url) = child_text("jdbc-url") else {
            continue;
        };
        out.push(Source {
            name: name.to_owned(),
            uuid: uuid.to_owned(),
            driver: child_text("driver-ref").unwrap_or_default(),
            jdbc_url,
            user: None,
            ssh_config_id: None,
        });
    }
    Ok(out)
}

/// `dataSources.local.xml`, keyed by uuid. Missing file = empty map: the user
/// name is a nicety, and its absence must not fail the import.
pub fn parse_local(xml: &str) -> Result<BTreeMap<String, Local>, String> {
    let doc = Document::parse(xml).map_err(|e| e.to_string())?;
    let mut out = BTreeMap::new();
    for node in doc.descendants().filter(|n| n.has_tag_name("data-source")) {
        let Some(uuid) = node.attribute("uuid") else {
            continue;
        };
        let user = node
            .children()
            .find(|c| c.has_tag_name("user-name"))
            .and_then(|c| c.text())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        // The tunnel counts only when DataGrip has it switched on: a stale
        // <ssh-config-id> stays in the file with <enabled>false</enabled>, and
        // importing it would tunnel a connection the user connects directly.
        let ssh = node.children().find(|c| c.has_tag_name("ssh-properties"));
        let ssh_enabled = ssh
            .and_then(|s| s.children().find(|c| c.has_tag_name("enabled")))
            .and_then(|c| c.text())
            .map(|t| t.trim() == "true")
            .unwrap_or(false);
        let ssh_config_id = ssh
            .filter(|_| ssh_enabled)
            .and_then(|s| s.children().find(|c| c.has_tag_name("ssh-config-id")))
            .and_then(|c| c.text())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        out.insert(
            uuid.to_owned(),
            Local {
                user,
                ssh_config_id,
            },
        );
    }
    Ok(out)
}

/// `sshConfigs.xml`, keyed by the id the data sources refer to.
pub fn parse_ssh_configs(xml: &str) -> Result<BTreeMap<String, SshConfig>, String> {
    let doc = Document::parse(xml).map_err(|e| e.to_string())?;
    let mut out = BTreeMap::new();
    for node in doc.descendants().filter(|n| n.has_tag_name("sshConfig")) {
        let (Some(id), Some(host)) = (node.attribute("id"), node.attribute("host")) else {
            continue;
        };
        out.insert(
            id.to_owned(),
            SshConfig {
                host: host.to_owned(),
                port: node.attribute("port").and_then(|p| p.parse().ok()),
                username: node.attribute("username").map(str::to_owned),
            },
        );
    }
    Ok(out)
}

/// Project paths from `recentProjects.xml` — the only reliable way to find
/// `.idea/dataSources.xml` files, which live wherever the user put the
/// project. `$USER_HOME$` is JetBrains' macro for the home directory.
pub fn parse_recent_projects(xml: &str, home: &Path) -> Result<Vec<PathBuf>, String> {
    let doc = Document::parse(xml).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for node in doc.descendants().filter(|n| n.has_tag_name("entry")) {
        let Some(key) = node.attribute("key") else {
            continue;
        };
        out.push(expand_user_home(key, home));
    }
    Ok(out)
}

fn expand_user_home(path: &str, home: &Path) -> PathBuf {
    match path.strip_prefix("$USER_HOME$/") {
        Some(rest) => home.join(rest),
        None => PathBuf::from(path),
    }
}

/// Join the three files into decisions, one per data source.
///
/// `used` belongs to the caller because aliases have to be unique across the
/// WHOLE import, and the import reads one file per project: two projects
/// naming a database `prod-01` is ordinary, and two `[connections.prod-01]`
/// sections are a TOML parse error that breaks every later nyet call.
pub fn map_sources(
    sources: &[Source],
    ssh_configs: &BTreeMap<String, SshConfig>,
    used: &mut BTreeMap<String, u32>,
) -> Vec<Mapped> {
    sources
        .iter()
        .map(|s| map_one(s, ssh_configs, used))
        .collect()
}

fn map_one(
    source: &Source,
    ssh_configs: &BTreeMap<String, SshConfig>,
    used: &mut BTreeMap<String, u32>,
) -> Mapped {
    let skip = |reason: String| Mapped::Skipped {
        name: source.name.clone(),
        reason,
    };
    let Some(engine) = engine_for(&source.driver) else {
        return skip(format!(
            "driver `{}` — nyet speaks postgres, mysql, mariadb, sqlite, mongodb, clickhouse and redis",
            if source.driver.is_empty() { "?" } else { &source.driver }
        ));
    };
    let stripped = source
        .jdbc_url
        .strip_prefix("jdbc:")
        .unwrap_or(&source.jdbc_url);

    if engine == "sqlite" {
        // sqlite jdbc is `jdbc:sqlite:/path/to.db` — no authority, so the url
        // crate is the wrong tool and nyet wants `path` anyway.
        let path = stripped.strip_prefix("sqlite:").unwrap_or(stripped);
        if path.is_empty() {
            return skip("the jdbc url carries no file path".to_owned());
        }
        return Mapped::Ready(Connection {
            alias: unique_alias(&source.name, used),
            source_name: source.name.clone(),
            engine,
            url: path.to_owned(),
            is_sqlite: true,
            wants_password: false,
            ssh: None,
            note: None,
        });
    }

    // ClickHouse is the one rewrite: DataGrip's `clickhouse://host:8123/db` is
    // the HTTP interface, and that is exactly what nyet's url must name.
    let (url, note) = if engine == "clickhouse" {
        let rest = stripped.strip_prefix("clickhouse://").unwrap_or(stripped);
        (
            format!("http://{rest}"),
            Some("rewritten to the HTTP interface; use https:// and the TLS port if the server has one".to_owned()),
        )
    } else {
        (stripped.to_owned(), None)
    };

    let parsed = match url::Url::parse(&url) {
        Ok(u) => u,
        Err(e) => return skip(format!("could not read the jdbc url ({e})")),
    };
    let Some(host) = parsed.host_str() else {
        return skip("the jdbc url names no host".to_owned());
    };

    let user = source.user.as_deref().filter(|u| !u.is_empty());
    let url = match user {
        // The url crate re-encodes on set_username, which is what we want for
        // a name like `domain\user`; on failure we keep the url userless
        // rather than emit a mangled one.
        Some(u) if parsed.username().is_empty() => {
            let mut with_user = parsed.clone();
            match with_user.set_username(u) {
                Ok(()) => with_user.to_string(),
                Err(()) => url,
            }
        }
        _ => url,
    };

    let ssh = source
        .ssh_config_id
        .as_deref()
        .and_then(|id| ssh_configs.get(id))
        .map(|cfg| Tunnel {
            host: format_ssh_host(cfg),
            // Behind a tunnel the jdbc address is the one reachable FROM the
            // bastion, so it is the forward's far end verbatim.
            remote: match parsed.port() {
                Some(port) => format!("{host}:{port}"),
                None => host.to_owned(),
            },
        });

    Mapped::Ready(Connection {
        alias: unique_alias(&source.name, used),
        source_name: source.name.clone(),
        engine,
        url,
        is_sqlite: false,
        wants_password: user.is_some() || !parsed.username().is_empty(),
        ssh,
        note,
    })
}

fn format_ssh_host(cfg: &SshConfig) -> String {
    let mut host = match &cfg.username {
        Some(u) if !u.is_empty() => format!("{u}@{}", cfg.host),
        _ => cfg.host.clone(),
    };
    if let Some(port) = cfg.port {
        host.push_str(&format!(":{port}"));
    }
    host
}

/// DataGrip's `driver-ref` is a family plus an optional version (`mongo.4`,
/// `sqlite.xerial`), so the family is the part before the first dot.
fn engine_for(driver: &str) -> Option<&'static str> {
    let family = driver.split('.').next().unwrap_or_default().to_lowercase();
    match family.as_str() {
        "postgresql" | "postgres" | "redshift" => Some("postgres"),
        "mysql" => Some("mysql"),
        "mariadb" => Some("mariadb"),
        "sqlite" => Some("sqlite"),
        "mongo" | "mongodb" => Some("mongodb"),
        "clickhouse" => Some("clickhouse"),
        "redis" | "valkey" => Some("redis"),
        _ => None,
    }
}

/// A DataGrip name is free text (`prod-taxi (6)`), a nyet alias is typed by an
/// agent on the command line. Keep it recognizable, drop what needs quoting.
pub fn alias_for(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut last_dash = true; // leading dashes are trimmed by the same rule
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            out.push(ch);
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        "connection".to_owned()
    } else {
        out
    }
}

fn unique_alias(name: &str, used: &mut BTreeMap<String, u32>) -> String {
    let base = alias_for(name);
    let count = used.entry(base.clone()).or_insert(0);
    *count += 1;
    if *count == 1 {
        base
    } else {
        format!("{base}-{count}")
    }
}

/// The TOML the human reviews (and the `--write` path appends). Comments are
/// part of the output, so this is written by hand rather than serialized.
pub fn render(mapped: &[Mapped], origin: &str) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "# Imported by `nyet import datagrip` from {origin}.\n"
    ));
    out.push_str("# Review before use: `allowed_dirs = []` denies every directory (fail\n");
    out.push_str("# closed), and passwords are references, not values — see the notes below.\n");

    for entry in mapped {
        let Mapped::Ready(conn) = entry else { continue };
        out.push('\n');
        if conn.alias != conn.source_name {
            out.push_str(&format!("# DataGrip: {}\n", conn.source_name));
        }
        if let Some(note) = &conn.note {
            out.push_str(&format!("# {note}\n"));
        }
        out.push_str(&format!("[connections.{}]\n", conn.alias));
        out.push_str(&format!("engine = {}\n", toml_string(conn.engine)));
        let key = if conn.is_sqlite { "path" } else { "url" };
        out.push_str(&format!("{key} = {}\n", toml_string(&conn.url)));
        if conn.wants_password {
            out.push_str(&format!(
                "password = {{ keychain = {} }}  # nyet secret-set {}\n",
                toml_string(&conn.alias),
                conn.alias
            ));
        }
        out.push_str("allowed_dirs = []  # name the directories this connection serves\n");
        if let Some(ssh) = &conn.ssh {
            out.push_str(&format!("\n[connections.{}.ssh]\n", conn.alias));
            out.push_str(&format!("host = {}\n", toml_string(&ssh.host)));
            out.push_str(&format!("remote = {}\n", toml_string(&ssh.remote)));
        }
    }
    out
}

/// A basic TOML string. The values are file paths, urls and names from someone
/// else's config, so quotes and backslashes have to survive the trip.
fn toml_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCES: &str = r#"
    <project version="4">
      <component name="DataSourceManagerImpl">
        <data-source name="prod-1000" uuid="u1">
          <driver-ref>mongo.4</driver-ref>
          <jdbc-url>mongodb://db.internal:27017/common?authSource=admin</jdbc-url>
        </data-source>
        <data-source name="prod-taxi (6)" uuid="u2">
          <driver-ref>postgresql</driver-ref>
          <jdbc-url>jdbc:postgresql://pg.internal:6432/app</jdbc-url>
        </data-source>
        <data-source name="legacy" uuid="u3">
          <driver-ref>oracle</driver-ref>
          <jdbc-url>jdbc:oracle:thin:@//ora:1521/x</jdbc-url>
        </data-source>
      </component>
    </project>"#;

    const LOCAL: &str = r#"
    <project version="4">
      <component name="dataSourceStorageLocal">
        <data-source name="prod-1000" uuid="u1">
          <user-name>reader</user-name>
          <ssh-properties>
            <enabled>true</enabled>
            <ssh-config-id>ssh1</ssh-config-id>
          </ssh-properties>
        </data-source>
        <data-source name="prod-taxi (6)" uuid="u2">
          <user-name>app</user-name>
          <ssh-properties>
            <enabled>false</enabled>
            <ssh-config-id>ssh1</ssh-config-id>
          </ssh-properties>
        </data-source>
      </component>
    </project>"#;

    const SSH: &str = r#"
    <application>
      <component name="SshConfigs">
        <configs>
          <sshConfig authType="OPEN_SSH" host="bastion.corp" id="ssh1" port="22" username="deploy" />
        </configs>
      </component>
    </application>"#;

    fn joined() -> Vec<Mapped> {
        let mut sources = parse_sources(SOURCES).unwrap();
        let local = parse_local(LOCAL).unwrap();
        for s in &mut sources {
            if let Some(l) = local.get(&s.uuid) {
                s.user = l.user.clone();
                s.ssh_config_id = l.ssh_config_id.clone();
            }
        }
        map_sources(
            &sources,
            &parse_ssh_configs(SSH).unwrap(),
            &mut BTreeMap::new(),
        )
    }

    #[test]
    fn an_unsupported_driver_is_named_not_dropped() {
        let skipped: Vec<_> = joined()
            .into_iter()
            .filter_map(|m| match m {
                Mapped::Skipped { name, reason } => Some((name, reason)),
                Mapped::Ready(_) => None,
            })
            .collect();
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].0, "legacy");
        assert!(skipped[0].1.contains("oracle"), "{}", skipped[0].1);
    }

    #[test]
    fn the_user_name_from_the_local_file_lands_in_the_url() {
        let toml = render(&joined(), "test");
        assert!(toml.contains("mongodb://reader@db.internal:27017/common?authSource=admin"));
        assert!(toml.contains("postgresql://app@pg.internal:6432/app"));
    }

    #[test]
    fn a_disabled_tunnel_is_not_imported() {
        let toml = render(&joined(), "test");
        // prod-1000 has it enabled, prod-taxi does not.
        assert!(toml.contains("[connections.prod-1000.ssh]"));
        assert!(!toml.contains("[connections.prod-taxi-6.ssh]"));
        assert!(toml.contains(r#"host = "deploy@bastion.corp:22""#));
        assert!(toml.contains(r#"remote = "db.internal:27017""#));
    }

    #[test]
    fn every_connection_is_denied_everywhere_until_the_human_edits_it() {
        let toml = render(&joined(), "test");
        // Counted as emitted KEYS, not as occurrences of the text: the header
        // comment explains `allowed_dirs = []` and would otherwise be counted.
        let keys = toml
            .lines()
            .filter(|l| l.starts_with("allowed_dirs = []"))
            .count();
        assert_eq!(keys, 2);
    }

    #[test]
    fn passwords_are_references_never_values() {
        let toml = render(&joined(), "test");
        assert!(
            toml.contains(r#"password = { keychain = "prod-1000" }  # nyet secret-set prod-1000"#)
        );
        assert!(!toml.to_lowercase().contains("master_key"));
    }

    #[test]
    fn a_name_that_needs_quoting_becomes_an_alias_that_does_not() {
        assert_eq!(alias_for("prod-taxi (6)"), "prod-taxi-6");
        assert_eq!(alias_for("  "), "connection");
        assert_eq!(alias_for("Прод"), "connection");
        assert_eq!(alias_for("db.prod"), "db-prod");
    }

    #[test]
    fn two_sources_with_one_name_get_two_aliases() {
        let mut used = BTreeMap::new();
        assert_eq!(unique_alias("prod", &mut used), "prod");
        assert_eq!(unique_alias("prod", &mut used), "prod-2");
        assert_eq!(unique_alias("prod!", &mut used), "prod-3");
    }

    #[test]
    fn sqlite_becomes_a_path_and_asks_for_no_password() {
        let xml = r#"<project><data-source name="dev" uuid="u">
          <driver-ref>sqlite.xerial</driver-ref>
          <jdbc-url>jdbc:sqlite:/home/me/dev.db</jdbc-url>
        </data-source></project>"#;
        let mapped = map_sources(
            &parse_sources(xml).unwrap(),
            &BTreeMap::new(),
            &mut BTreeMap::new(),
        );
        let toml = render(&mapped, "test");
        assert!(toml.contains(r#"path = "/home/me/dev.db""#));
        assert!(!toml.lines().any(|l| l.starts_with("password = ")));
    }

    #[test]
    fn clickhouse_is_rewritten_to_the_http_interface_and_says_so() {
        let xml = r#"<project><data-source name="ch" uuid="u">
          <driver-ref>clickhouse</driver-ref>
          <jdbc-url>jdbc:clickhouse://ch.internal:8123/analytics</jdbc-url>
        </data-source></project>"#;
        let mapped = map_sources(
            &parse_sources(xml).unwrap(),
            &BTreeMap::new(),
            &mut BTreeMap::new(),
        );
        let toml = render(&mapped, "test");
        assert!(toml.contains(r#"url = "http://ch.internal:8123/analytics""#));
        assert!(toml.contains("# rewritten to the HTTP interface"));
    }

    #[test]
    fn a_quote_in_a_name_cannot_break_out_of_the_generated_toml() {
        assert_eq!(toml_string(r#"a"b\c"#), r#""a\"b\\c""#);
    }

    #[test]
    fn recent_projects_expand_the_home_macro() {
        let xml = r#"<application><component name="RecentProjectsManager">
          <option name="additionalInfo"><map>
            <entry key="$USER_HOME$/DataGripProjects/x"><value/></entry>
            <entry key="/abs/path"><value/></entry>
          </map></option></component></application>"#;
        let got = parse_recent_projects(xml, Path::new("/home/me")).unwrap();
        assert_eq!(
            got,
            vec![
                PathBuf::from("/home/me/DataGripProjects/x"),
                PathBuf::from("/abs/path"),
            ]
        );
    }

    #[test]
    fn a_malformed_file_is_an_error_not_a_silent_empty_import() {
        assert!(parse_sources("<project><data-source").is_err());
    }
}
