//! Redis/Valkey layer 1 (W8): pure classification of one command line into
//! Allow/Deny. Depends on nothing but std, and the golden corpus in
//! `tests/corpus/redis/` runs it without a live server.
//!
//! **Where the classification comes from, and where it does not.** Redis
//! publishes its own read/write classification — `COMMAND INFO <name>` returns
//! flags (`readonly`, `write`, `admin`, `blocking`) and ACL categories
//! (`@read`, `@write`, `@dangerous`, ...) — so unlike MongoDB, nyet keeps no
//! list of what every command does. Measured on `redis:7.4` (August 2026), the
//! server is honest about the cases that matter and that a hand-written list
//! would have got wrong:
//!
//! - `GETEX` is `write` ("RW and UPDATE because it changes the TTL");
//! - `GETDEL`, `SPOP`, `SORT`, `BITFIELD`, `GEORADIUS` are `write`, and their
//!   `_RO` twins are `readonly`;
//! - `SCAN` is `readonly`, and its cursor is NOT server state: cursor 8 taken
//!   on one connection continued correctly on another (so the ROADMAP's worry
//!   about a server-side cursor did not reproduce);
//! - an unknown name returns nil, which fails closed for free.
//!
//! What the flags do NOT decide is in `DENIED_COMMANDS` below, and the rule
//! this module applies on top of them is in [`check`].
//!
//! Layer 2 does not exist here at all, and nyet says so rather than inventing
//! one: Redis has no read-only session and no read-only transaction. The
//! nearest thing is a replica (`replica-read-only`) or an ACL user
//! (`+@read -@write`), and both of those are layer 3 — a recommendation
//! `nyet doctor` checks and nags about.

use std::collections::BTreeSet;

/// What the SERVER said about one command, reduced to the four properties the
/// policy reads. Built by the engine from `COMMAND INFO`; pure here so the
/// corpus can pin the policy without a live server.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Flags {
    /// The server marked it `readonly`. Its ABSENCE is what refuses — not the
    /// presence of `write` — so a command that is neither (the scripting
    /// family, `SUBSCRIBE`, `INFO`) fails closed without nyet having to know
    /// what it is.
    pub readonly: bool,
    /// The server marked it `write`. This is the HARD boundary: a command the
    /// server itself calls a write is refused and `allow_functions` cannot
    /// reach it, because a read-only tool that can be configured into writing
    /// is not a read-only tool. Every other refusal below is a policy the
    /// connection's owner may overrule.
    pub write: bool,
    /// `admin`: server administration, never data.
    pub admin: bool,
    /// `blocking`: the command may hold the connection until something happens
    /// (`XREAD ... BLOCK`, `BLPOP`). A read tool that can be made to wait is a
    /// read tool that can be made to hang.
    pub blocking: bool,
    /// The `@dangerous` ACL category. Redis puts it on the commands that are a
    /// hazard to the SERVER rather than to the data — `KEYS` (O(N) on a
    /// single-threaded server), `SORT_RO` (whose BY/GET patterns read keys the
    /// command never names), `INFO`, `DEBUG`, `MONITOR`, `CONFIG`, `CLIENT
    /// LIST`. Some of them are perfectly good reads, which is why
    /// `validator.allow_functions` reaches them (see [`check`]).
    pub dangerous: bool,
}

/// A refusal, shaped like the SQL validator's so the cli maps both the same
/// way. `reason` is from the closed contract list.
#[derive(Debug)]
pub struct Refusal {
    pub reason: DenyReason,
    pub message: String,
    pub hint: String,
}

/// Closed list; the strings are part of the agent-facing contract
/// (`error.reason` under `error.code = "NYET"`). Append-only.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DenyReason {
    /// The command line could not be split into a command and its arguments.
    ParseFailed,
    /// The server does not classify this command as a read.
    WriteOperation,
    /// nyet's own denylist, or `validator.deny_functions` for this connection.
    DeniedCommand,
    /// **nyet could not ASK what this command does.** Not a verdict about the
    /// command — a verdict about the setup: the account may not run
    /// `COMMAND INFO`, so the classification layer 1 rests on is unavailable and
    /// everything fails closed.
    ///
    /// Its own reason rather than a borrowed one, because it is the one Redis
    /// refusal an agent must NOT respond to by rewriting the command: no
    /// rewrite fixes it, and only the person who owns the ACL can. (Measured:
    /// `COMMAND` is not in `@read`, so the read-only account nyet itself
    /// recommends hit this until the recipe learned to grant `+command|info`.)
    Unclassified,
}

impl DenyReason {
    pub fn as_str(self) -> &'static str {
        match self {
            DenyReason::ParseFailed => "PARSE_FAILED",
            DenyReason::WriteOperation => "WRITE_OPERATION",
            DenyReason::DeniedCommand => "DENIED_COMMAND",
            DenyReason::Unclassified => "UNCLASSIFIED",
        }
    }
}

/// One parsed command line. `name` and `sub` are lowercased; `args` keep the
/// caller's bytes exactly, because they are DATA (a key name is case-sensitive
/// in Redis, and so is everything else).
#[derive(Debug, PartialEq, Eq)]
pub struct Command {
    pub name: String,
    /// The container subcommand, when this command has one (`OBJECT ENCODING`,
    /// `XINFO STREAM`). Redis classifies container commands per SUBcommand, and
    /// `COMMAND INFO "object|encoding"` answers for exactly that — so nyet asks
    /// the same question it is going to run.
    pub sub: Option<String>,
    pub args: Vec<String>,
}

impl Command {
    /// The name `COMMAND INFO` is asked about: `object|encoding` for a
    /// container command, the bare name otherwise.
    pub fn lookup_name(&self) -> String {
        match &self.sub {
            Some(sub) => format!("{}|{sub}", self.name),
            None => self.name.clone(),
        }
    }

    /// The full argument vector to send on the wire, name first.
    pub fn wire(&self) -> Vec<&str> {
        let mut out = vec![self.name.as_str()];
        if let Some(sub) = &self.sub {
            out.push(sub.as_str());
        }
        out.extend(self.args.iter().map(String::as_str));
        out
    }
}

/// Commands whose CONTAINER form takes a subcommand, as of Redis 7.4. Redis
/// classifies these per SUBcommand — `CONFIG GET` is `admin`, `OBJECT ENCODING`
/// is `readonly` — so the name nyet asks `COMMAND INFO` about has to be the
/// subcommand's (`config|get`), or the answer is about the container, which
/// carries no flags at all.
///
/// **Not a security list.** A container missing from it fails CLOSED: the
/// lookup falls back to the bare name, the container entry has no `readonly`
/// flag, and the command is refused. What a missing entry costs is precision —
/// the refusal says "the server does not classify `config` as a read" instead
/// of "`config|get` is an administrative command" — and one readonly
/// subcommand that should have been allowed (`OBJECT ENCODING` was refused
/// exactly this way while `config` was missing from the list).
const CONTAINERS: &[&str] = &[
    "acl", "client", "cluster", "command", "config", "function", "latency", "memory", "object",
    "pubsub", "script", "slowlog", "xgroup", "xinfo",
];

/// nyet's own denylist, ON TOP of what the server's flags refuse. Every entry
/// is here because a flag says "readonly" (or says nothing useful) about
/// something nyet is not willing to run. Config-tunable through
/// `validator.deny_functions` / `validator.allow_functions`, which for Redis
/// name COMMANDS.
///
/// **Scripting, and why the whole family goes.** `EVAL_RO` and `FCALL_RO` are
/// flagged `readonly` by the server (measured on 7.4), so the flag rule alone
/// would let them through. nyet refuses them for the same reason MongoDB
/// refuses `$where` and `$function`: the payload is a program in another
/// language, and layer 1's whole claim is that it understood what it forwarded.
/// Parsing Lua to prove it only reads was rejected on MongoDB and is rejected
/// here — a validator for a second language is a second validator to be wrong.
///
/// There is a sharper, measurable half as well: Redis executes a script on the
/// single server thread and does not preempt it. A script that loops makes the
/// server answer BUSY to every other client until somebody runs `SCRIPT KILL`,
/// and `EVAL_RO`'s read-only guarantee does nothing about that. The
/// `pg_sleep`/`BENCHMARK` class, with the whole server as the blast radius.
const DENIED_COMMANDS: &[&str] = &[
    "eval",
    "eval_ro",
    "evalsha",
    "evalsha_ro",
    "fcall",
    "fcall_ro",
    "function",
    "script",
];

/// Split one command line into a command, an optional subcommand and its
/// arguments — `redis-cli` quoting, and nothing more clever than that.
///
/// Quoting exists because a Redis key or value is arbitrary bytes and routinely
/// holds spaces (`GET "user session:42"`). Inside double quotes `\\` escapes the
/// next character; inside single quotes nothing does, which is the shell rule
/// and the one people expect. An unterminated quote is a parse error, not a
/// guess — fail closed like every other boundary.
///
/// **No `;` splitting and no multi-command form.** One call runs one command,
/// full stop: the wire protocol sends arguments length-prefixed, so a newline
/// or a `\r\n` inside an argument is DATA and cannot start a second command —
/// but nyet refuses a literal control character anyway, so that guarantee does
/// not silently become a property of whichever client library is linked in.
pub fn parse(line: &str) -> Result<Command, Refusal> {
    // Before tokenizing, not after: `\r` and `\n` are WHITESPACE to the
    // tokenizer, so an unquoted `GET a\rb` would quietly split into three
    // tokens and run a command the caller did not write. Refusing them up front
    // is the fail-closed reading, and it covers the quoted case in the same
    // line. Tab survives as an ordinary separator.
    if let Some(bad) = line.chars().find(|c| c.is_control() && *c != '\t') {
        return Err(Refusal {
            reason: DenyReason::ParseFailed,
            message: format!(
                "the command contains the control character U+{:04X}, which nyet does not send",
                bad as u32
            ),
            hint: "remove the newline / carriage return / NUL: nyet runs exactly one command \
                   per call, and it refuses text it would have to reinterpret to do so"
                .to_string(),
        });
    }
    let mut tokens: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut started = false;
    let mut quote: Option<char> = None;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some('"'), '\\') => match chars.next() {
                Some(escaped) => {
                    current.push(escaped);
                    started = true;
                }
                None => return Err(unterminated()),
            },
            (Some(q), c) if c == q => {
                quote = None;
            }
            (Some(_), c) => {
                current.push(c);
                started = true;
            }
            (None, '"' | '\'') => {
                quote = Some(c);
                started = true;
            }
            (None, c) if c.is_whitespace() => {
                if started {
                    tokens.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            (None, c) => {
                current.push(c);
                started = true;
            }
        }
    }
    if quote.is_some() {
        return Err(unterminated());
    }
    if started {
        tokens.push(current);
    }
    // A `\`-escape inside double quotes can produce a control character the
    // scan above never saw (`"a\` followed by a real newline is caught there,
    // but `\` + `n` is not a newline — this is about the byte, not the
    // spelling). Belt and braces on the tokens themselves.
    if let Some(bad) = tokens.iter().find(|t| t.chars().any(is_control)) {
        return Err(Refusal {
            reason: DenyReason::ParseFailed,
            message: format!(
                "the command contains a control character in {:?}, which nyet does not send",
                truncate(bad)
            ),
            hint: "remove the newline / carriage return / NUL from the argument; if the value \
                   itself needs one, that is a write, and nyet does not write"
                .to_string(),
        });
    }
    let mut tokens = tokens.into_iter();
    let Some(name) = tokens.next() else {
        return Err(Refusal {
            reason: DenyReason::ParseFailed,
            message: "the command is empty".to_string(),
            hint: "pass one Redis command, e.g. \"GET some:key\" or \"HGETALL user:42\""
                .to_string(),
        });
    };
    let name = name.to_lowercase();
    let mut args: Vec<String> = tokens.collect();
    // A container command's SUBcommand decides its flags, so it has to be split
    // off before `COMMAND INFO` is asked anything.
    let sub = match CONTAINERS.contains(&name.as_str()) && !args.is_empty() {
        true => Some(args.remove(0).to_lowercase()),
        false => None,
    };
    Ok(Command { name, sub, args })
}

/// Is this the layer-1 decision? Yes — and it is deliberately short, because
/// the classification it rests on comes from the server.
///
/// `flags` is `None` when `COMMAND INFO` did not recognise the name, which is
/// the fail-closed case Redis hands over for free (an unknown command returns
/// nil). The rule, in order:
///
/// 1. nyet's own `DENIED_COMMANDS` (merged with the connection's
///    `validator.deny_functions`, minus its `allow_functions`) — refused
///    whatever the server says about them;
/// 2. the server must KNOW the command;
/// 3. the server must flag it `readonly`. The absence of that flag refuses,
///    rather than the presence of `write`: `EVAL`, `SUBSCRIBE` and `INFO` carry
///    neither, and a rule written the other way would have let all three
///    through;
/// 4. `admin`, `blocking` and `@dangerous` refuse on top. `@dangerous` is the
///    one that costs something real — it takes `KEYS`, `SORT_RO` and `INFO`
///    with it.
///
/// Steps 3 and 4 are POLICY, and `validator.allow_functions` overrules them by
/// NAME: `allow_functions = ["keys", "info"]` puts those two back on a
/// connection whose owner decided they are fine there. Step 0 is not policy and
/// nothing overrules it — **a command the SERVER flags `write` is refused,
/// full stop.** A read-only tool that can be configured into writing is not a
/// read-only tool, so `allow_functions = ["set"]` buys nothing. That is the one
/// place Redis differs from the SQL engines' `allow_functions`, and it differs
/// because there the statement allowlist refuses `INSERT` no matter what the
/// function list says — here this rule IS that allowlist.
pub fn check(
    command: &Command,
    flags: Option<Flags>,
    denied: &BTreeSet<String>,
    allowed: &BTreeSet<String>,
) -> Result<(), Refusal> {
    let name = command.lookup_name();
    if denied.contains(&name) || denied.contains(&command.name) {
        return Err(Refusal {
            reason: DenyReason::DeniedCommand,
            message: format!("nyet: the command '{name}' is on the denylist for this connection"),
            hint: format!(
                "'{}' is refused whatever the server says about it — the scripting family runs \
                 a program nyet cannot read, on the thread that serves every other client. If \
                 the connection's owner disagrees, add it to validator.allow_functions for \
                 this connection in the config",
                command.name
            ),
        });
    }
    if flags.is_some_and(|f| f.write) {
        return Err(Refusal {
            reason: DenyReason::WriteOperation,
            message: format!("nyet: the server classifies '{name}' as a write command"),
            hint: read_hint(&command.name),
        });
    }
    let Some(flags) = flags else {
        return Err(Refusal {
            reason: DenyReason::WriteOperation,
            message: format!(
                "nyet: the server does not know a command called '{}', so nyet cannot tell \
                 whether it reads or writes",
                command.name
            ),
            hint: "check the spelling; nyet asks the SERVER (COMMAND INFO) what every command \
                   does and refuses anything it will not classify"
                .to_string(),
        });
    };
    // The connection's owner overruling the POLICY half — the flags that are
    // about hazard and about "the server would not call this a read", never
    // about the server calling it a write (that was settled above and is not
    // reachable from here). Kept apart from `denylist` because taking a name
    // off nyet's own list and overruling Redis's own `@dangerous` are two
    // different decisions, and only this one can put `KEYS` back on a
    // production key space.
    if allowed.contains(&name) || allowed.contains(&command.name) {
        return Ok(());
    }
    // Ordered by how much the message TELLS the reader, not by how the rule is
    // written: "this is administrative" and "this blocks" are both sharper than
    // "the server would not call it a read", so they are answered first, even
    // though the readonly rule would refuse the same commands.
    let (what, why) = if flags.admin {
        (
            "an administrative command",
            "it operates the server rather than reading data",
        )
    } else if flags.blocking {
        (
            "a blocking command",
            "it can hold the connection until something happens, which is a read tool that can \
             be made to hang",
        )
    } else if !flags.readonly {
        return Err(Refusal {
            reason: DenyReason::WriteOperation,
            message: format!(
                "nyet: the server does not classify '{name}' as a read (COMMAND INFO reports \
                 neither a `readonly` nor a `write` flag, so nyet cannot tell what it does)"
            ),
            hint: format!(
                "{}. If the connection's owner knows this one is a read, \
                 validator.allow_functions = [\"{name}\"] says so",
                read_hint(&command.name)
            ),
        });
    } else if flags.dangerous {
        (
            "in the @dangerous ACL category",
            "Redis puts commands there that are a hazard to the SERVER rather than to the data \
             — KEYS walks the whole key space on a single-threaded process, SORT_RO's BY/GET \
             patterns read keys the command never names, INFO and CLIENT LIST publish the \
             server's internals",
        )
    } else {
        return Ok(());
    };
    Err(Refusal {
        reason: DenyReason::DeniedCommand,
        message: format!("nyet: '{name}' is {what}: {why}"),
        hint: format!(
            "if this connection's owner wants it anyway, add it to validator.allow_functions \
             (for Redis those name commands: allow_functions = [\"{name}\"])"
        ),
    })
}

/// The hint for a command the server does not call a read. Split out because
/// the useful half is naming the read-only twin where one exists — a refusal
/// that only says no is a refusal that teaches nothing (D10).
fn read_hint(name: &str) -> String {
    let twin = match name {
        "getex" => Some(("GET", "GETEX moves the key's TTL, which is a write")),
        "getdel" => Some(("GET", "GETDEL removes the key")),
        "spop" => Some(("SRANDMEMBER", "SPOP removes the member it returns")),
        "sort" => Some(("SORT_RO", "SORT can STORE its result")),
        "bitfield" => Some(("BITFIELD_RO", "BITFIELD can SET fields")),
        "georadius" => Some(("GEORADIUS_RO", "GEORADIUS can STORE its result")),
        "georadiusbymember" => Some((
            "GEORADIUSBYMEMBER_RO",
            "GEORADIUSBYMEMBER can STORE its result",
        )),
        "blpop" | "brpop" | "blmpop" | "bzpopmin" | "bzpopmax" => {
            Some(("LRANGE / ZRANGE", "the B* commands pop, and they block"))
        }
        _ => None,
    };
    match twin {
        Some((instead, why)) => format!("{why}; use {instead} instead"),
        None => "nyet is read-only; use the command's read-only form if it has one (SORT_RO, \
                 BITFIELD_RO, GEORADIUS_RO, EVAL_RO's family is refused separately), or rewrite \
                 the task as a read"
            .to_string(),
    }
}

/// The refusal for an account that may not ask the server what a command does.
/// Built here rather than in the engine so the wording (and the ACL line it
/// prints) lives with the rule it belongs to.
pub fn unclassified(detail: &str) -> Refusal {
    Refusal {
        reason: DenyReason::Unclassified,
        message: format!(
            "nyet: this account may not run COMMAND INFO, so nyet cannot ask the server \
             whether a command reads or writes — and it will not guess ({detail})"
        ),
        hint: "this is not something the command can be rewritten around: the account needs \
               the metadata command. Grant it — it publishes nothing but command signatures, \
               which are the same on every Redis of this version:\n\
               ACL SETUSER <user> +command|info +info\n\
               (`+info` is what `nyet schema` reads the key counts with)"
            .to_string(),
    }
}

/// The effective denylist for a connection: nyet's own list minus
/// `allow_functions`, plus `deny_functions`. Deny wins when a name is in both
/// (fail closed) — the same merge rule as the SQL validator's.
pub fn denylist(allow: &[String], deny: &[String]) -> BTreeSet<String> {
    let mut set: BTreeSet<String> = DENIED_COMMANDS.iter().map(|c| c.to_lowercase()).collect();
    for name in allow {
        set.remove(&name.to_lowercase());
    }
    for name in deny {
        set.insert(name.to_lowercase());
    }
    set
}

/// `allow_functions` as an exemption set for the FLAG rules (`@dangerous` and
/// friends), lowercased. Deliberately separate from `denylist`: removing a name
/// from nyet's own list and overriding the server's classification are two
/// different permissions, and only the second one can put `KEYS` back.
pub fn allowlist(allow: &[String]) -> BTreeSet<String> {
    allow.iter().map(|name| name.to_lowercase()).collect()
}

fn unterminated() -> Refusal {
    Refusal {
        reason: DenyReason::ParseFailed,
        message: "the command has an unterminated quote".to_string(),
        hint: "close the \" or ' — nyet refuses anything it cannot split into a command and its \
               arguments (fail closed)"
            .to_string(),
    }
}

/// Control characters, tab included: by the time the tokens exist, tab has
/// already done its job as a separator, so one INSIDE an argument got there
/// through quoting and is refused like the rest.
fn is_control(c: char) -> bool {
    c.is_control()
}

/// Trim a value before it goes into an error message — the argument is the
/// caller's own text, but a 2 MB one has no business in the envelope.
fn truncate(text: &str) -> String {
    let mut out: String = text.chars().take(40).collect();
    if out.chars().count() < text.chars().count() {
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmd(line: &str) -> Command {
        parse(line).unwrap_or_else(|r| panic!("{line}: {}", r.message))
    }

    fn ro() -> Flags {
        Flags {
            readonly: true,
            ..Flags::default()
        }
    }

    #[test]
    fn quoting_follows_redis_cli() {
        assert_eq!(cmd("GET foo").wire(), vec!["get", "foo"]);
        assert_eq!(cmd("  GET   foo  ").wire(), vec!["get", "foo"]);
        // A key with a space is why quoting exists at all.
        assert_eq!(
            cmd(r#"GET "user session:42""#).wire(),
            vec!["get", "user session:42"]
        );
        assert_eq!(cmd("GET 'a b'").wire(), vec!["get", "a b"]);
        // Backslash escapes inside double quotes, not inside single ones.
        assert_eq!(cmd(r#"GET "a\"b""#).wire(), vec!["get", "a\"b"]);
        assert_eq!(cmd(r"GET 'a\b'").wire(), vec!["get", r"a\b"]);
        // An EMPTY argument is a real Redis key and must survive.
        assert_eq!(cmd(r#"GET """#).wire(), vec!["get", ""]);
        // The command name is folded, the arguments never are.
        assert_eq!(cmd("HgEtAlL User:1").wire(), vec!["hgetall", "User:1"]);
    }

    #[test]
    fn an_unterminated_quote_fails_closed() {
        for line in [r#"GET "abc"#, "GET 'abc", r#"GET "a\"#] {
            assert_eq!(
                parse(line).unwrap_err().reason,
                DenyReason::ParseFailed,
                "{line}"
            );
        }
    }

    /// The wire protocol sends arguments length-prefixed, so a newline inside
    /// one cannot start a second command. nyet refuses it anyway, so that
    /// guarantee is a rule of nyet's rather than a property of whichever client
    /// library happens to be linked in.
    #[test]
    fn a_control_character_is_refused_even_though_the_wire_would_survive_it() {
        for line in ["GET a\rb", "GET a\nb", "SET x\r\nFLUSHALL"] {
            assert_eq!(
                parse(line).unwrap_err().reason,
                DenyReason::ParseFailed,
                "{line}"
            );
        }
    }

    #[test]
    fn container_commands_are_classified_per_subcommand() {
        let c = cmd("OBJECT ENCODING mykey");
        assert_eq!(c.lookup_name(), "object|encoding");
        assert_eq!(c.wire(), vec!["object", "encoding", "mykey"]);
        let c = cmd("XINFO STREAM s");
        assert_eq!(c.lookup_name(), "xinfo|stream");
        // A non-container command keeps its second word as an argument.
        let c = cmd("GET STREAM");
        assert_eq!(c.lookup_name(), "get");
        assert_eq!(c.args, vec!["STREAM"]);
    }

    #[test]
    fn the_absence_of_readonly_is_what_refuses() {
        let denied = denylist(&[], &[]);
        let allowed = allowlist(&[]);
        // Neither `readonly` nor `write`: SUBSCRIBE, INFO and the scripting
        // family all look like this, and a rule keyed on `write` would have
        // passed every one of them.
        let err = check(
            &cmd("SUBSCRIBE ch"),
            Some(Flags::default()),
            &denied,
            &allowed,
        )
        .unwrap_err();
        assert_eq!(err.reason, DenyReason::WriteOperation);
        assert!(check(&cmd("GET k"), Some(ro()), &denied, &allowed).is_ok());
    }

    #[test]
    fn an_unknown_command_fails_closed() {
        let err = check(
            &cmd("NOSUCHCMD k"),
            None,
            &denylist(&[], &[]),
            &allowlist(&[]),
        )
        .unwrap_err();
        assert_eq!(err.reason, DenyReason::WriteOperation);
        assert!(err.message.contains("does not know"));
    }

    /// The scripting family is refused BEFORE the flags are consulted, which is
    /// the whole point: the server calls `EVAL_RO` a read.
    #[test]
    fn scripting_is_refused_even_though_the_server_calls_it_readonly() {
        let denied = denylist(&[], &[]);
        let allowed = allowlist(&[]);
        for line in [
            "EVAL_RO \"return 1\" 0",
            "FCALL_RO f 0",
            "EVAL \"return 1\" 0",
            "EVALSHA abc 0",
            "SCRIPT LOAD \"return 1\"",
            "FUNCTION LIST",
        ] {
            let err = check(&cmd(line), Some(ro()), &denied, &allowed).unwrap_err();
            assert_eq!(err.reason, DenyReason::DeniedCommand, "{line}");
        }
    }

    #[test]
    fn the_dangerous_category_refuses_reads_and_the_config_can_take_it_back() {
        let dangerous = Flags {
            readonly: true,
            dangerous: true,
            ..Flags::default()
        };
        let err = check(
            &cmd("KEYS *"),
            Some(dangerous),
            &denylist(&[], &[]),
            &allowlist(&[]),
        )
        .unwrap_err();
        assert_eq!(err.reason, DenyReason::DeniedCommand);
        assert!(err.message.contains("@dangerous"));
        // The escape hatch: the connection's owner overrules the server's own
        // hazard flag for this one name.
        let allowed = allowlist(&["keys".to_string()]);
        assert!(check(
            &cmd("KEYS *"),
            Some(dangerous),
            &denylist(&[], &[]),
            &allowed
        )
        .is_ok());
        // ...and it is scoped to that name, not to the category.
        assert!(check(&cmd("INFO"), Some(dangerous), &denylist(&[], &[]), &allowed).is_err());
    }

    #[test]
    fn deny_functions_adds_and_allow_functions_removes() {
        let allowed = allowlist(&[]);
        // A connection that does not want SCAN.
        let denied = denylist(&[], &["scan".to_string()]);
        assert_eq!(
            check(&cmd("SCAN 0"), Some(ro()), &denied, &allowed)
                .unwrap_err()
                .reason,
            DenyReason::DeniedCommand
        );
        // A connection that has decided EVAL_RO is fine.
        let denied = denylist(&["eval_ro".to_string()], &[]);
        assert!(check(&cmd("EVAL_RO x 0"), Some(ro()), &denied, &allowed).is_ok());
        // Deny wins over allow (fail closed).
        let denied = denylist(&["eval".to_string()], &["eval".to_string()]);
        assert!(check(&cmd("EVAL x 0"), Some(ro()), &denied, &allowed).is_err());
    }
}

#[cfg(test)]
mod corpus {
    use super::*;
    use std::path::Path;

    /// Golden corpus (D6) — the public specification of what Redis layer 1
    /// accepts. Lives in `tests/corpus/redis/` (a SUBdirectory, so the SQL
    /// corpus runner, which reads `tests/corpus/*.yaml`, does not hand Redis
    /// commands to sqlparser) and uses the same tiny line format, plus one key
    /// the other engines do not need.
    ///
    /// **`flags:` is the honest part of this file.** Redis's classification
    /// comes from the SERVER (`COMMAND INFO`), so a corpus that runs without one
    /// has to bring the answer with it. Each case carries the flags the live
    /// `redis:7.4` reported for that command, transcribed; what is under test
    /// is the RULE, which is the part nyet owns. `flags: unknown` is the nil the
    /// server returns for a name it does not have, and `flags: none` is a
    /// command it flags neither way.
    #[test]
    fn golden_corpus() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/redis");
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "yaml"))
            .collect();
        files.sort();
        assert!(!files.is_empty(), "no corpus files in {}", dir.display());
        let mut total = 0;
        for file in files {
            let name = file.file_name().unwrap().to_string_lossy().into_owned();
            let text = std::fs::read_to_string(&file).unwrap();
            let mut cases: Vec<Case> = Vec::new();
            for (idx, raw) in text.lines().enumerate() {
                let line = raw.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Some(q) = line.strip_prefix("- query: ") {
                    cases.push(Case {
                        line: idx + 1,
                        query: q.to_string(),
                        ..Case::default()
                    });
                    continue;
                }
                let case = cases
                    .last_mut()
                    .unwrap_or_else(|| panic!("{name}:{}: key before first '- query:'", idx + 1));
                if let Some(v) = line.strip_prefix("verdict: ") {
                    case.verdict = v.to_string();
                } else if let Some(r) = line.strip_prefix("reason: ") {
                    case.reason = Some(r.to_string());
                } else if let Some(f) = line.strip_prefix("flags: ") {
                    case.flags = Some(f.to_string());
                } else if let Some(a) = line.strip_prefix("allow_functions: ") {
                    case.allow = split(a);
                } else if let Some(d) = line.strip_prefix("deny_functions: ") {
                    case.deny = split(d);
                } else {
                    panic!("{name}:{}: unrecognized corpus line: {raw}", idx + 1);
                }
            }
            for case in cases {
                total += 1;
                let at = format!("{name}:{} {:?}", case.line, case.query);
                let flags = case.flags.as_deref().unwrap_or_else(|| {
                    panic!(
                        "{at}: no flags: line — the server's answer is \
                                               part of the case, not something the test may \
                                               guess"
                    )
                });
                let denied = denylist(&case.allow, &case.deny);
                let allowed = allowlist(&case.allow);
                let verdict = parse(&case.query)
                    .and_then(|command| check(&command, parse_flags(flags), &denied, &allowed));
                match verdict {
                    Ok(()) => {
                        assert_eq!(case.verdict, "allow", "{at}: got allow");
                        assert!(case.reason.is_none(), "{at}: reason on an allow case");
                    }
                    Err(r) => {
                        assert_eq!(case.verdict, "deny", "{at}: got deny ({})", r.message);
                        assert_eq!(
                            case.reason.as_deref(),
                            Some(r.reason.as_str()),
                            "{at}: wrong reason"
                        );
                        // D10: a refusal without an actionable hint does not ship.
                        assert!(!r.message.is_empty(), "{at}: empty message");
                        assert!(!r.hint.is_empty(), "{at}: empty hint");
                    }
                }
            }
        }
        // Tripwire against accidental corpus loss.
        assert!(total >= 90, "corpus suspiciously small: {total} cases");
    }

    #[derive(Default)]
    struct Case {
        line: usize,
        query: String,
        flags: Option<String>,
        verdict: String,
        reason: Option<String>,
        allow: Vec<String>,
        deny: Vec<String>,
    }

    fn split(text: &str) -> Vec<String> {
        text.split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect()
    }

    /// `flags: readonly,dangerous` -> the `Flags` the engine would have built
    /// from `COMMAND INFO`. `unknown` is the nil reply (an absent command).
    fn parse_flags(text: &str) -> Option<Flags> {
        if text == "unknown" {
            return None;
        }
        let words: Vec<&str> = text.split(',').map(str::trim).collect();
        let has = |flag: &str| words.contains(&flag);
        for word in &words {
            assert!(
                [
                    "readonly",
                    "write",
                    "admin",
                    "blocking",
                    "dangerous",
                    "none"
                ]
                .contains(word),
                "unknown flag in corpus: {word:?}"
            );
        }
        Some(Flags {
            readonly: has("readonly"),
            write: has("write"),
            admin: has("admin"),
            blocking: has("blocking"),
            dangerous: has("dangerous"),
        })
    }
}
