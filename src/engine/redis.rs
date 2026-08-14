//! Redis/Valkey (W8), over redis-rs's low-level `cmd()`.
//!
//! Three things are different here from every other engine, and each one is
//! reported rather than papered over:
//!
//! - **There is no layer 2.** Redis has no read-only session, no read-only
//!   transaction, no `readonly=1`. What exists is a replica
//!   (`replica-read-only`) and an ACL user (`+@read -@write`), and both of
//!   those are layer 3. `nyet doctor` says `na` for layer 2 and checks layer 3
//!   for real.
//! - **The classification comes from the server.** `COMMAND INFO` is asked
//!   about the exact command that is about to run, and `crate::redis::check`
//!   decides. One extra round trip per query, and no list of 250 commands to
//!   keep current.
//! - **There is no schema.** `nyet schema` answers `na` and reports what costs
//!   nothing: the per-database key counts `INFO keyspace` already publishes. A
//!   `SCAN` of a production key space is a scan of production, and nyet does
//!   not do that on its own initiative.

use super::{
    client_timeout, connect_deadline, error_parts, ConnectFact, Diagnosis, Engine, EngineError,
    ProbeFact, ResultSet, ServerFacts, SuperuserFact,
};
use crate::guardrail::{CostEstimate, Guardrail};
use crate::output::{Schema, SchemaDatabase};
use crate::validator::Origin;
use redis::{Value, VerbatimFormat};
use serde_json::Map;
use std::collections::BTreeSet;
use std::time::Duration;

/// Redis over redis-rs. `url` is `redis://[user[:password]@]host[:port][/db]`,
/// or `rediss://` for TLS.
pub struct Redis {
    pub url: String,
    pub password: Option<String>,
    /// The in-process query deadline. Redis has no server-side statement
    /// timeout for a single command, so this is the ONLY bound — the same
    /// position SQLite is in.
    pub query_timeout_ms: u64,
    /// Filled in by `open_tunnel`: the local end of the SSH forward.
    pub host_override: Option<(String, u16)>,
    /// Tests only: shorten the connect deadline.
    pub connect_timeout_ms: Option<u64>,
    /// The effective command denylist for this connection (nyet's own list
    /// tuned by `validator.deny_functions` / `allow_functions`).
    pub denied: BTreeSet<String>,
    /// `validator.allow_functions`, as the override for the SERVER's own hazard
    /// flags (`@dangerous`, `admin`, `blocking`).
    pub allowed: BTreeSet<String>,
}

impl Redis {
    /// Open one connection, in RESP3.
    ///
    /// RESP3 is not a preference, it is what makes the output contract
    /// possible: in RESP2 a `HGETALL` reply and a `LRANGE` reply are both a flat
    /// array and nothing on the wire tells them apart, so nyet would have to
    /// keep a table of which command returns a map — the very list this engine
    /// exists to avoid. In RESP3 the server sends a typed Map, and the shape of
    /// the answer follows from the shape of the reply (see `shape`).
    async fn open(&self) -> Result<redis::aio::MultiplexedConnection, EngineError> {
        // Parsed through redis-rs's own `FromStr`, not by hand: a
        // userinfo/host/port split written here would be a second opinion about
        // the string the driver is going to dial.
        let info: redis::ConnectionInfo =
            self.dialed_url()?
                .parse()
                .map_err(|_| EngineError::Connect {
                    // The driver's parse error can quote the offending url, so
                    // only the fixed explanation goes out — a url may carry a
                    // password (the rule the whole cli keeps).
                    message: "the connection url is not a valid Redis url".to_string(),
                    hint: HINT_URL.to_string(),
                })?;
        let mut settings = info
            .redis_settings()
            .clone()
            .set_protocol(redis::ProtocolVersion::RESP3);
        // The explicit `password` field wins over one written in the url, the
        // same precedence every other engine keeps.
        if let Some(password) = &self.password {
            settings = settings.set_password(password);
        }
        let info = info.set_redis_settings(settings);
        let client = redis::Client::open(info).map_err(|_| EngineError::Connect {
            message: "the connection url could not be turned into a Redis client".to_string(),
            hint: HINT_URL.to_string(),
        })?;
        let deadline = self.connect_timeout_ms.map_or_else(
            || connect_deadline(self.query_timeout_ms),
            Duration::from_millis,
        );
        match tokio::time::timeout(deadline, client.get_multiplexed_async_connection()).await {
            Err(_elapsed) => Err(EngineError::Connect {
                message: format!(
                    "could not reach the Redis server within {}s",
                    deadline.as_secs()
                ),
                hint: "check the host and port, and that the server is reachable from here \
                       (through the ssh tunnel, if the connection has one)"
                    .to_string(),
            }),
            Ok(Err(e)) => Err(EngineError::Connect {
                message: format!("could not connect to Redis: {}", first_line(&e.to_string())),
                hint: "check the host, the port, and the credentials (Redis 6+ takes a user \
                       name as well as a password)"
                    .to_string(),
            }),
            Ok(Ok(connection)) => Ok(connection),
        }
    }

    /// The url as it will actually be dialed: the tunnel's local end replaces
    /// host and port and nothing else, so user, password, database and the TLS
    /// decision ride along — the same rule as the other server engines.
    fn dialed_url(&self) -> Result<String, EngineError> {
        let Some((host, port)) = &self.host_override else {
            return Ok(self.url.clone());
        };
        let mut parsed = url::Url::parse(&self.url).map_err(|_| EngineError::Connect {
            message: "the connection url is not a valid Redis url".to_string(),
            hint: HINT_URL.to_string(),
        })?;
        let bad_host = || EngineError::Connect {
            message: "the tunnel's local address could not be put into the connection url"
                .to_string(),
            hint: HINT_URL.to_string(),
        };
        parsed.set_host(Some(host)).map_err(|_| bad_host())?;
        parsed.set_port(Some(*port)).map_err(|()| bad_host())?;
        Ok(parsed.to_string())
    }

    /// Run one already-classified command inside the query deadline.
    async fn run(
        &self,
        connection: &mut redis::aio::MultiplexedConnection,
        args: &[&str],
    ) -> Result<Value, EngineError> {
        let mut cmd = redis::cmd(args[0]);
        for arg in &args[1..] {
            cmd.arg(*arg);
        }
        let deadline = Duration::from_millis(self.query_timeout_ms);
        match tokio::time::timeout(deadline, cmd.query_async(connection)).await {
            Err(_elapsed) => Err(client_timeout(self.query_timeout_ms)),
            Ok(Err(e)) => Err(EngineError::Db {
                message: first_line(&e.to_string()),
                hint: "check the command and its arguments against the server's own docs; nyet \
                       forwards them unchanged"
                    .to_string(),
            }),
            Ok(Ok(value)) => Ok(value),
        }
    }

    /// What the SERVER says about this command. `COMMAND INFO` is the whole
    /// classification layer: no list, no guessing, and an unknown name comes
    /// back nil, which fails closed.
    ///
    /// A failure to ASK is not an answer: it returns `Err`, and the caller
    /// refuses rather than running an unclassified command. The refusal an
    /// ACL-denied lookup produces is its own reason (`UNCLASSIFIED`), because
    /// no rewrite of the command fixes it — measured, `COMMAND` is not in
    /// `@read`, so the read-only account nyet itself recommends hit this on
    /// every single query until the recipe learned to grant `+command|info`.
    async fn flags(
        &self,
        connection: &mut redis::aio::MultiplexedConnection,
        name: &str,
    ) -> Result<Option<crate::redis::Flags>, EngineError> {
        let reply = match self.run(connection, &["COMMAND", "INFO", name]).await {
            Ok(reply) => reply,
            Err(e) => {
                let (detail, hint) = error_parts(e);
                return Err(match detail.to_uppercase().contains("NOPERM") {
                    true => refusal_error(crate::redis::unclassified(&detail)),
                    false => EngineError::Db {
                        message: detail,
                        hint,
                    },
                });
            }
        };
        // `COMMAND INFO x` answers with a one-element array; the element is nil
        // for an unknown command.
        let entry = match reply {
            Value::Array(entries) | Value::Set(entries) => entries.into_iter().next(),
            other => Some(other),
        };
        let Some(entry) = entry else { return Ok(None) };
        let fields = match entry {
            Value::Array(fields) => fields,
            // Nil, or anything that is not the documented reply shape: nyet did
            // not learn what this command does, so it must not run it.
            _ => return Ok(None),
        };
        // Fields are [name, arity, flags, first_key, last_key, step,
        // acl_categories, tips, key_specs, subcommands]. Only the flag arrays
        // matter, and both are read the same way — a flat list of strings, some
        // prefixed `@` for the ACL categories.
        let words: Vec<String> = fields
            .iter()
            .skip(2)
            .filter_map(|f| match f {
                Value::Array(items) | Value::Set(items) => Some(items),
                _ => None,
            })
            .flatten()
            .filter_map(text_of)
            .map(|s| s.to_lowercase())
            .collect();
        let has = |flag: &str| words.iter().any(|w| w == flag);
        Ok(Some(crate::redis::Flags {
            readonly: has("readonly"),
            write: has("write"),
            admin: has("admin"),
            blocking: has("blocking"),
            dangerous: has("@dangerous"),
        }))
    }

    /// Layer 1 again, on the very command about to run — the same reflex as the
    /// other engines' re-validation. The cli classified this text already; doing
    /// it here means what EXECUTES is what was CLASSIFIED, with no second
    /// representation in between to drift.
    async fn classified(
        &self,
        connection: &mut redis::aio::MultiplexedConnection,
        line: &str,
    ) -> Result<crate::redis::Command, EngineError> {
        let command = crate::redis::parse(line).map_err(refusal_error)?;
        let flags = self.flags(connection, &command.lookup_name()).await?;
        crate::redis::check(&command, flags, &self.denied, &self.allowed).map_err(refusal_error)?;
        Ok(command)
    }
}

const HINT_URL: &str = "use url = \"redis://user@host:6379/0\" (or rediss:// for TLS); the \
                        database number is optional and defaults to 0";

/// A layer-1 refusal made HERE. Unlike the other engines' re-validation, this
/// one is the real verdict and not a should-never-happen backstop: the flag half
/// of the Redis policy needs `COMMAND INFO`, so it cannot be reached before
/// connecting. It travels as a refusal — NYET + reason, exit 5 — because that is
/// what it is; a DB_ERROR would teach the agent that its command was malformed
/// when the answer is that nyet does not run that command.
fn refusal_error(r: crate::redis::Refusal) -> EngineError {
    EngineError::Refused {
        reason: r.reason.as_str(),
        message: r.message,
        hint: r.hint,
    }
}

/// The first line of a driver/server message, trimmed. Redis error text names
/// the command and the reason and never the url.
fn first_line(text: &str) -> String {
    text.lines().next().unwrap_or("").trim().to_string()
}

/// The text of a RESP value, when it has one.
fn text_of(value: &Value) -> Option<String> {
    match value {
        Value::SimpleString(s) => Some(s.clone()),
        Value::BulkString(bytes) => Some(String::from_utf8_lossy(bytes).into_owned()),
        Value::VerbatimString { text, .. } => Some(text.clone()),
        _ => None,
    }
}

/// One RESP value as JSON. Bytes that are valid UTF-8 become a string; bytes
/// that are not become a string too, with the invalid sequences replaced —
/// **lossily and deliberately**. A Redis value is arbitrary bytes and a JSON
/// string is not, so something has to give; the same choice the SQL engines
/// make for invalid UTF-8 text, and losing a byte in a displayed value beats
/// failing the whole read.
fn json(value: &Value) -> serde_json::Value {
    match value {
        Value::Nil => serde_json::Value::Null,
        Value::Int(n) => serde_json::Value::from(*n),
        Value::Double(f) => serde_json::Number::from_f64(*f)
            .map_or(serde_json::Value::Null, serde_json::Value::Number),
        Value::Boolean(b) => serde_json::Value::Bool(*b),
        Value::SimpleString(s) => serde_json::Value::String(s.clone()),
        Value::Okay => serde_json::Value::String("OK".to_string()),
        Value::BulkString(bytes) => {
            serde_json::Value::String(String::from_utf8_lossy(bytes).into_owned())
        }
        Value::VerbatimString { format, text } => match format {
            // The one verbatim format Redis actually sends is `txt`; anything
            // else keeps its text and loses only the format tag, which no
            // reader of this contract has a use for.
            VerbatimFormat::Text | VerbatimFormat::Markdown | VerbatimFormat::Unknown(_) => {
                serde_json::Value::String(text.clone())
            }
            // Forced by `#[non_exhaustive]`; the TEXT is the answer in every
            // format Redis defines, and the format tag has no place in the
            // contract anyway.
            _ => serde_json::Value::String(text.clone()),
        },
        // A big number arrives as raw digits; it stays a STRING because that is
        // the only rendering that cannot round it.
        Value::BigNumber(bytes) => {
            serde_json::Value::String(String::from_utf8_lossy(bytes).into_owned())
        }
        Value::Array(items) | Value::Set(items) | Value::Push { data: items, .. } => {
            serde_json::Value::Array(items.iter().map(json).collect())
        }
        Value::Map(pairs) => {
            let mut object = Map::new();
            for (key, value) in pairs {
                // A map KEY that is not text keeps its JSON rendering as the
                // key, which is the only way to put it in a JSON object at all.
                let key = text_of(key).unwrap_or_else(|| json(key).to_string());
                object.insert(key, json(value));
            }
            serde_json::Value::Object(object)
        }
        Value::Attribute { data, .. } => json(data),
        Value::ServerError(e) => serde_json::Value::String(format!("{e:?}")),
        // `redis::Value` is `#[non_exhaustive]`, so this arm is forced rather
        // than chosen. It renders the value instead of dropping it: a RESP type
        // a future redis-rs adds must show up in the answer as SOMETHING the
        // reader can see and report, not as a silent null.
        other => serde_json::Value::String(format!("{other:?}")),
    }
}

/// The output contract for Redis, decided by the SHAPE of the RESP3 reply and
/// never by a table of which command returns what (W8, owner's call):
///
/// - a **Map** (`HGETALL`, `CONFIG GET`, `XINFO STREAM`) -> two columns,
///   `field` and `value`, one row per entry;
/// - an **Array or Set** (`LRANGE`, `SMEMBERS`, `XRANGE`, `SCAN`) -> one column
///   `value`, one row per top-level element;
/// - anything **scalar** (`GET`, `EXISTS`, `TTL`, `TYPE`, nil) -> one column
///   `value`, one row.
///
/// A nested element keeps its structure inside the cell as JSON — `XRANGE`
/// gives one row per stream entry, each holding `[id, [field, value, ...]]`.
/// That is the honest shape: nyet does not know that a stream entry is an id
/// and a field list, and inventing columns for it would be the guess this
/// design exists to avoid.
///
/// RESP3 is what makes this work: in RESP2 the first two cases are the same
/// flat array on the wire.
fn shape(value: Value) -> (Vec<String>, Vec<Vec<serde_json::Value>>) {
    match value {
        Value::Map(pairs) => (
            vec!["field".to_string(), "value".to_string()],
            pairs
                .iter()
                .map(|(k, v)| {
                    vec![
                        text_of(k).map_or_else(|| json(k), serde_json::Value::String),
                        json(v),
                    ]
                })
                .collect(),
        ),
        Value::Array(items) | Value::Set(items) | Value::Push { data: items, .. } => (
            vec!["value".to_string()],
            items.iter().map(|item| vec![json(item)]).collect(),
        ),
        // An attribute wraps the real reply; unwrap and shape THAT, or the row
        // would be the metadata instead of the answer.
        Value::Attribute { data, .. } => shape(*data),
        scalar => (vec!["value".to_string()], vec![vec![json(&scalar)]]),
    }
}

impl Engine for Redis {
    /// The guardrail parameter is ignored, like SQLite's and MongoDB's: Redis
    /// publishes no plan and no estimate of any kind, so `off` is the only mode
    /// its config accepts (`guardrail::engine_modes`).
    async fn execute(
        &self,
        sql: &str,
        fetch_limit: u64,
        _guardrail: &Guardrail,
    ) -> Result<super::QueryOutcome, EngineError> {
        let mut connection = self.open().await?;
        let command = self.classified(&mut connection, sql).await?;
        let value = self.run(&mut connection, &command.wire()).await?;
        let (columns, mut rows) = shape(value);
        // Truncation is CLIENT side and it is late: the whole reply is already
        // in this process by the time it is counted, because Redis has no LIMIT
        // and no cursor for a command that returns everything. `LRANGE k 0 -1`
        // on a ten-million-element list transfers ten million elements whatever
        // `--limit` says. The limit still bounds what the AGENT is handed (and
        // therefore its context window), and SECURITY.md records the rest.
        //
        // `ResultSet::truncated` stays FALSE, and that is not an oversight: it
        // means "the SERVER stopped short of what nyet asked for", which never
        // happens here — nyet has the whole reply. The row limit is applied by
        // the cli, which counts the rows it got against the limit and sets
        // `meta.truncated` itself. Setting it here as well would be a second
        // opinion about the same thing.
        rows.truncate(fetch_limit as usize);
        Ok(super::QueryOutcome::Ran {
            result: ResultSet {
                // A Redis reply has no provenance of any kind: there are no
                // tables and no columns, so there is nothing for a `[pii]`
                // policy to key on. Config parse refuses `[pii]` on a Redis
                // connection outright (see config::validate_redis), so these
                // Unknowns are never judged.
                origins: vec![Origin::Unknown; columns.len()],
                columns,
                rows,
                truncated: false,
            },
            estimate: None,
        })
    }

    /// Redis publishes no plan for anything. `Ok(None)` is the honest answer,
    /// and the cli turns it into `verdict: no_estimate` with a warning rather
    /// than inventing a number (UX-7).
    ///
    /// Layer 1 still runs: `explain` must never be the way around the classifier.
    async fn estimate(&self, sql: &str) -> Result<Option<CostEstimate>, EngineError> {
        let mut connection = self.open().await?;
        self.classified(&mut connection, sql).await?;
        Ok(None)
    }

    /// **`na`, plus the one thing that costs nothing.** Redis has no schema, no
    /// tables and no collections. The only way to describe its contents is to
    /// walk the key space, and `SCAN` over a production key space is a scan of
    /// production — for an answer that is a guess about the shape of a key
    /// naming convention. So nyet does not do it on its own initiative, says
    /// so, and reports what `INFO keyspace` already publishes for free: how
    /// many keys each database holds, and how many of them have a TTL. The
    /// agent still learns the scale, which is what it was really asking.
    ///
    /// `table` (the agent's `[table]` argument) is deliberately ignored rather
    /// than turned into a key lookup: `nyet schema <alias> some:key` reads as
    /// "describe this object", and answering it with a TYPE would be a
    /// different command wearing this one's name.
    async fn schema(&self, _table: Option<&str>) -> Result<Schema, EngineError> {
        let mut connection = self.open().await?;
        // `INFO` is not in `@read` either, so the recommended read-only account
        // may well be refused it. That is NOT a reason to fail the command: the
        // honest answer to "what is the schema" is `na` with or without the key
        // counts, so a refused INFO costs the counts and says so in the same
        // breath — it must not read as "this database is empty".
        let (databases, note) = match self.run(&mut connection, &["INFO", "keyspace"]).await {
            Ok(reply) => (
                parse_keyspace(&text_of(&reply).unwrap_or_default()),
                String::new(),
            ),
            Err(e) => (
                Vec::new(),
                format!(
                    " The per-database key counts are missing from this answer because the \
                     account may not run INFO ({}) — grant `+info` for them; their absence \
                     here is not a claim that the key space is empty.",
                    error_parts(e).0
                ),
            ),
        };
        Ok(Schema {
            tables: Vec::new(),
            na: Some(format!("{SCHEMA_NA}{note}")),
            databases,
        })
    }

    /// **No layer 2 to remove, so the probe is the whole story.** Every other
    /// engine's probe exists to strip nyet's read-only session and see what the
    /// server does; here there was never a session to strip, so what this
    /// measures is simply whether these credentials can write. It uses the
    /// server's own ACL rather than a write: `ACL WHOAMI` + `ACL GETUSER` name
    /// the user's command rules, so nyet learns the answer without touching a
    /// key — the MongoDB shape, for the same reason (a probe write into a live
    /// cache is not a thing a read-only tool should do, and there is no
    /// transaction to roll it back with).
    async fn diagnose(&self, _pii: &[(String, String)]) -> Diagnosis {
        let mut connection = match self.open().await {
            Ok(connection) => connection,
            Err(e) => {
                let (message, hint) = error_parts(e);
                return Diagnosis {
                    connect: ConnectFact::Failed { message, hint },
                    server: None,
                    pii: Vec::new(),
                    pii_views: None,
                };
            }
        };
        // Layer 1's own liveness, checked FIRST because it is the one failure
        // that makes every other verdict here moot.
        let classifier_error = self
            .flags(&mut connection, "get")
            .await
            .err()
            .map(|e| error_parts(e).0);
        let acl = self.acl_rules(&mut connection).await;
        let replica = self.replica_note(&mut connection).await;
        let (probe, superuser) = match &acl {
            // The account may not read its own ACL — and that is what the
            // RECOMMENDED account looks like: `ACL WHOAMI` needs the `acl`
            // command, which lives in @admin, so a properly locked-down user
            // gets NOPERM here (measured on 7.4 with
            // `-@all +@read +@keyspace`). Reporting "could not verify" for
            // exactly the setup nyet asks for would make the check useless, so
            // it falls back to the one proof that needs no privilege: try a
            // write and see.
            Err(detail) => (
                self.write_probe(&mut connection, detail, replica.as_deref())
                    .await,
                // A NOPERM on `acl|whoami` is not "could not verify" for THIS
                // question: `+@all` includes the `acl` command, so an account
                // that may not run it provably does not hold `+@all`. Any other
                // failure to ask stays Unknown -> warn.
                match detail.to_uppercase().contains("NOPERM") {
                    true => SuperuserFact::No(format!(
                        "this account may not even run ACL WHOAMI, so it cannot hold +@all \
                         (which includes it): {detail}"
                    )),
                    false => SuperuserFact::Unknown(detail.clone()),
                },
            ),
            Ok(rules) => (probe_of(rules, replica.as_deref()), superuser_of(rules)),
        };
        Diagnosis {
            connect: ConnectFact::Ok {
                via_tunnel: self.host_override.is_some(),
            },
            server: Some(ServerFacts {
                superuser,
                read_only_note: replica,
                probe,
                js: None,
                readonly: None,
                classifier_error,
            }),
            // Redis has no columns, so a `[pii]` policy cannot exist here —
            // config parse refuses one (config::validate_redis).
            pii: Vec::new(),
            pii_views: None,
        }
    }
}

/// The `na` reason, in the payload so a machine reader gets it too rather than
/// only a human reading the warning.
const SCHEMA_NA: &str = "Redis has no schema: no tables, no collections, no declared fields. \
                         Describing its contents would mean SCANning the key space, which is a \
                         scan of production for an answer that is still a guess — so nyet does \
                         not do it, and reports the per-database key counts INFO keyspace \
                         publishes for free instead. To look at keys, run SCAN yourself: \
                         `nyet query <alias> \"SCAN 0 MATCH prefix:* COUNT 100\"`.";

impl Redis {
    /// The command rules of the CURRENT user, from `ACL WHOAMI` + `ACL
    /// GETUSER`. `Err` carries why it could not be asked — reported as "could
    /// not verify", never as a pass.
    async fn acl_rules(
        &self,
        connection: &mut redis::aio::MultiplexedConnection,
    ) -> Result<String, String> {
        let who = self
            .run(connection, &["ACL", "WHOAMI"])
            .await
            .map_err(|e| error_parts(e).0)?;
        let who = text_of(&who).ok_or_else(|| "ACL WHOAMI returned no user name".to_string())?;
        let reply = self
            .run(connection, &["ACL", "GETUSER", &who])
            .await
            .map_err(|e| format!("{} (asking about the user `{who}`)", error_parts(e).0))?;
        // The reply is a map in RESP3 and a flat array in RESP2; nyet always
        // speaks RESP3, and the `commands` entry is the one that matters. The
        // whole reply is rendered rather than picked apart, because what makes
        // a user read-only differs by deployment (`+@read`, `-@write`,
        // `-@all +get`, ...) and the honest thing is to show the rule.
        let rendered = json(&reply);
        rendered
            .get("commands")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| "the server did not report this account's command rules".to_string())
    }

    /// The fallback proof of layer 3, for an account that may not read its own
    /// ACL: attempt a write and see what the server says.
    ///
    /// The write is chosen so that succeeding costs as little as possible —
    /// this is the one place nyet deliberately writes, and it is writing into
    /// somebody's live cache:
    ///
    /// - `NX`, so it can never overwrite an existing key, whatever the name
    ///   collision;
    /// - `EX 1`, so a probe that DID land expires by itself one second later
    ///   even if the cleanup `DEL` is refused or the connection dies;
    /// - a name built from pid + nanoseconds + a counter (`probe_name`), which
    ///   cannot hit a real key.
    ///
    /// A refusal is only read as a refusal when the server SAYS so (`NOPERM`,
    /// or a replica's `READONLY`). Any other failure is `Unknown` -> warn: a
    /// false pass in a security tool is worse than a false warn (UX-1).
    async fn write_probe(
        &self,
        connection: &mut redis::aio::MultiplexedConnection,
        why_acl_failed: &str,
        replica: Option<&str>,
    ) -> ProbeFact {
        let key = super::probe_name();
        match self
            .run(connection, &["SET", &key, "1", "EX", "1", "NX"])
            .await
        {
            Err(e) => {
                let (detail, _) = error_parts(e);
                let upper = detail.to_uppercase();
                // Redis names both refusals in the error itself: NOPERM from the
                // ACL, READONLY from a replica.
                if upper.contains("NOPERM") || upper.contains("READONLY") {
                    let mut detail = format!(
                        "nyet could not read this account's ACL rules ({why_acl_failed}), so \
                         it probed instead: a SET was refused — {detail}"
                    );
                    if let Some(note) = replica {
                        detail.push_str(&format!("; {note}"));
                    }
                    return ProbeFact::Blocked {
                        detail,
                        ddl_only: false,
                    };
                }
                ProbeFact::Unknown {
                    detail: format!(
                        "nyet could not read this account's ACL rules ({why_acl_failed}), and \
                         the probe write failed for a reason that does not prove read-only: \
                         {detail}"
                    ),
                }
            }
            Ok(_) => {
                // Best effort: the key carries EX 1, so it goes away by itself
                // even if this is refused or never lands.
                let _ = self.run(connection, &["DEL", &key]).await;
                ProbeFact::Wrote { orphan: None }
            }
        }
    }

    /// Is this server a replica, and does it refuse writes because of it?
    /// `INFO replication` names the role, and `replica-read-only` (which a
    /// read-only ACL user may not read via CONFIG GET) is what makes the role
    /// mean something — so the note says exactly what was seen.
    async fn replica_note(
        &self,
        connection: &mut redis::aio::MultiplexedConnection,
    ) -> Option<String> {
        let reply = self.run(connection, &["INFO", "replication"]).await.ok()?;
        let text = text_of(&reply)?;
        let role = text
            .lines()
            .find_map(|line| line.trim().strip_prefix("role:"))?
            .trim()
            .to_string();
        (role == "slave").then(|| {
            "this server reports role:slave, so it is a replica — a replica refuses writes while \
             `replica-read-only` is on (its default)"
                .to_string()
        })
    }
}

/// What the ACL command rules mean for layer 3. Pure so the truth table is
/// unit-testable without a server, and fail-closed twice over: a rule nyet does
/// not recognise is `Unknown` (-> warn), never a pass.
fn probe_of(rules: &str, replica: Option<&str>) -> ProbeFact {
    let rules = rules.to_lowercase();
    // `+@all` (or its `allcommands` spelling) is every command, writes
    // included, whatever follows it — nyet does not evaluate the whole rule
    // algebra, so a later `-@write` is reported as unrecognised rather than
    // assumed to save it.
    let all = rules.contains("+@all") || rules.contains("allcommands");
    let subtracts_writes = rules.contains("-@write") || rules.contains("-@all");
    let adds_writes = rules.contains("+@write");
    if adds_writes || (all && !subtracts_writes) {
        return ProbeFact::Wrote { orphan: None };
    }
    if subtracts_writes && !adds_writes {
        let mut detail = format!("the account's ACL rules are `{rules}`");
        if let Some(note) = replica {
            detail.push_str(&format!("; {note}"));
        }
        return ProbeFact::Blocked {
            detail,
            // Not the DDL-vs-DML distinction the SQL engines make: Redis has no
            // DDL, and `-@write` covers every writing command there is. `false`
            // is therefore the accurate half — "every write is rejected".
            ddl_only: false,
        };
    }
    ProbeFact::Unknown {
        detail: format!(
            "nyet could not decide from the account's ACL rules whether it may write: `{rules}`"
        ),
    }
}

/// Does the account hold Redis's own everything-grant? `+@all` is exactly that,
/// and `@admin`/`@dangerous` are the halves that reconfigure or inspect the
/// server.
fn superuser_of(rules: &str) -> SuperuserFact {
    let rules = rules.to_lowercase();
    if rules.contains("+@all") || rules.contains("allcommands") {
        return SuperuserFact::Yes(format!(
            "this account holds +@all — every command, including CONFIG, DEBUG and FLUSHALL \
             (rules: `{rules}`)"
        ));
    }
    if rules.contains("+@admin") || rules.contains("+@dangerous") {
        return SuperuserFact::Yes(format!(
            "this account holds an administrative ACL category (rules: `{rules}`)"
        ));
    }
    SuperuserFact::No(format!("rules: `{rules}`"))
}

/// The `# Keyspace` section of `INFO`, which looks like
/// `db0:keys=203,expires=0,avg_ttl=0`. Pure, so the parsing is testable without
/// a server; an unparsable line is skipped rather than guessed at.
fn parse_keyspace(text: &str) -> Vec<SchemaDatabase> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        let Some((name, fields)) = line.split_once(':') else {
            continue;
        };
        if !name.starts_with("db") {
            continue;
        }
        let field = |key: &str| {
            fields
                .split(',')
                .find_map(|f| f.trim().strip_prefix(key))
                .and_then(|v| v.parse::<u64>().ok())
        };
        let Some(keys) = field("keys=") else { continue };
        out.push(SchemaDatabase {
            name: name.to_string(),
            keys,
            expires: field("expires=").unwrap_or(0),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_keyspace_section_is_read_and_nothing_else_is_guessed() {
        let text = "# Keyspace\r\ndb0:keys=203,expires=2,avg_ttl=0\r\ndb5:keys=1,expires=0\r\n\
                    garbage\r\nnotadb:keys=9\r\n";
        let dbs = parse_keyspace(text);
        assert_eq!(dbs.len(), 2);
        assert_eq!(dbs[0].name, "db0");
        assert_eq!(dbs[0].keys, 203);
        assert_eq!(dbs[0].expires, 2);
        assert_eq!(dbs[1].name, "db5");
        assert_eq!(dbs[1].keys, 1);
    }

    /// The RESP3 reply type is the whole contract: a Map becomes field/value
    /// pairs, an Array becomes one row per element, and nothing needs to know
    /// which command produced it.
    #[test]
    fn the_shape_follows_the_reply_type_not_the_command() {
        let (columns, rows) = shape(Value::Map(vec![
            (
                Value::BulkString(b"f1".to_vec()),
                Value::BulkString(b"v1".to_vec()),
            ),
            (
                Value::BulkString(b"f2".to_vec()),
                Value::BulkString(b"v2".to_vec()),
            ),
        ]));
        assert_eq!(columns, ["field", "value"]);
        assert_eq!(rows, [["f1", "v1"], ["f2", "v2"]]);

        let (columns, rows) = shape(Value::Array(vec![
            Value::BulkString(b"a".to_vec()),
            Value::BulkString(b"b".to_vec()),
        ]));
        assert_eq!(columns, ["value"]);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0][0], "a");

        let (columns, rows) = shape(Value::Int(7));
        assert_eq!(columns, ["value"]);
        assert_eq!(rows, [[serde_json::json!(7)]]);

        let (columns, rows) = shape(Value::Nil);
        assert_eq!(columns, ["value"]);
        assert_eq!(rows, [[serde_json::Value::Null]]);

        // A nested element keeps its structure in the cell — nyet does not know
        // that a stream entry is an id plus a field list, so it does not
        // pretend to.
        let entry = Value::Array(vec![
            Value::BulkString(b"1-0".to_vec()),
            Value::Array(vec![
                Value::BulkString(b"f".to_vec()),
                Value::BulkString(b"v".to_vec()),
            ]),
        ]);
        let (_, rows) = shape(Value::Array(vec![entry]));
        assert_eq!(rows[0][0], serde_json::json!(["1-0", ["f", "v"]]));
    }

    #[test]
    fn acl_rules_decide_layer_three_and_an_unreadable_rule_is_not_a_pass() {
        assert!(matches!(
            probe_of("-@all +@read", None),
            ProbeFact::Blocked {
                ddl_only: false,
                ..
            }
        ));
        assert!(matches!(
            probe_of("+@all -@write", None),
            // `+@all` followed by `-@write` is a rule nyet does not evaluate;
            // it says so instead of ruling either way.
            ProbeFact::Blocked { .. }
        ));
        assert!(matches!(probe_of("+@all", None), ProbeFact::Wrote { .. }));
        assert!(matches!(
            probe_of("-@all +@read +@write", None),
            ProbeFact::Wrote { .. }
        ));
        assert!(matches!(
            probe_of("+get +hgetall", None),
            ProbeFact::Unknown { .. }
        ));
        assert!(matches!(superuser_of("+@all"), SuperuserFact::Yes(_)));
        assert!(matches!(superuser_of("-@all +@read"), SuperuserFact::No(_)));
    }
}
