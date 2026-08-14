//! ClickHouse over its HTTP interface (W9).
//!
//! Two things make this engine different from the sqlx three, and both are
//! measured rather than assumed (`clickhouse-server:24.8-alpine`, August 2026):
//!
//! - **Layer 2 is a query parameter, not a transaction.** `readonly=1` rides in
//!   the request url, and it is the strongest layer 2 of any engine nyet
//!   supports: it refuses writes AND every settings change AND — the surprise —
//!   nearly every table function, `url`/`file`/`s3`/`remote`/`executable`
//!   included (`Code: 164 READONLY`). What it does NOT refuse is in
//!   `validator::CLICKHOUSE_DENIED_FUNCTIONS`, each entry marked with what was
//!   measured.
//! - **There is no session.** Every HTTP request is its own session, so the
//!   guardrail's EXPLAIN is a separate round trip rather than a savepoint in a
//!   shared transaction. That is simpler and it is also honest: nothing here can
//!   leak session state into the next call, because there is no next call.

use super::{
    client_timeout, connect_deadline, error_parts, listing, over_detail_limit, probe_name, sorted,
    ConnectFact, Diagnosis, Engine, EngineError, PiiAccess, ProbeFact, ReadonlyFact, ResultSet,
    SchemaColumn, SchemaIndex, ServerFacts, SuperuserFact, TableParts,
};
use crate::guardrail::{CostEstimate, Guardrail};
use crate::output::{KeyPart, Schema};
use crate::validator::Origin;
use http_body_util::BodyExt;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde_json::{Map, Value};
use std::time::Duration;

/// ClickHouse over HTTP. `url` is `http://user@host:8123/database` (or
/// `https://` — the scheme, not a query parameter, is what decides TLS here,
/// which is one fewer thing to get subtly wrong than `sslmode`).
pub struct Clickhouse {
    pub url: String,
    pub password: Option<String>,
    /// The server-side `max_execution_time`, in ms (sent as whole seconds —
    /// ClickHouse takes a float, but a sub-second cap would cut the handshake
    /// budget below what a WAN connect needs).
    pub statement_timeout_ms: u64,
    /// The in-process query-phase deadline that backstops the server cap.
    pub query_timeout_ms: u64,
    /// Filled in by `open_tunnel`: the local end of the SSH forward.
    pub host_override: Option<(String, u16)>,
    /// Tests only: shorten the connect deadline.
    pub connect_timeout_ms: Option<u64>,
}

/// The largest reply body nyet will read into memory, in bytes. ClickHouse
/// applies `max_result_rows` per QUERY, not per cell, so a thousand rows of
/// 10 MB strings is a perfectly legal answer to a bounded query — and this
/// process would hold all of it. The row limit is the contract; this is the
/// backstop that keeps a read-only tool from being the thing that dies.
/// Exceeding it is a DB_ERROR naming the cap, not a silent truncation (UX-1).
const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

/// How long the guardrail's own `EXPLAIN ESTIMATE` may take. It reads part
/// metadata rather than data, so this is generous; the point is that a slow one
/// cannot eat the budget of the query it guards.
const ESTIMATE_BUDGET_MS: u64 = 5_000;

impl Clickhouse {
    /// Clamp to what ClickHouse's `max_execution_time` accepts. It is a float of
    /// seconds; nyet sends whole seconds and never less than one, because 0
    /// means "no limit" — a rounding accident must not disarm the cap.
    pub fn clamp_statement_timeout(ms: u64) -> u64 {
        ms.max(1_000)
    }

    /// The parsed endpoint: scheme, authority (after any tunnel rewrite), user,
    /// database. Errors are `Connect` — a url nyet cannot read is a connection
    /// that will never happen, and the message never echoes the url (it may
    /// carry a password).
    fn endpoint(&self) -> Result<Endpoint, EngineError> {
        let parsed = url::Url::parse(&self.url).map_err(|_| EngineError::Connect {
            message: "the connection url is not a valid ClickHouse HTTP url".to_string(),
            hint: HINT_URL.to_string(),
        })?;
        let tls = match parsed.scheme() {
            "http" => false,
            "https" => true,
            _ => {
                return Err(EngineError::Connect {
                    message: "the connection url must use the http:// or https:// scheme — nyet \
                              talks to ClickHouse over its HTTP interface"
                        .to_string(),
                    hint: HINT_URL.to_string(),
                })
            }
        };
        let database = parsed.path().trim_matches('/').to_string();
        if database.is_empty() || database.contains('/') {
            return Err(EngineError::Connect {
                message: "the connection url names no database (nyet never picks one on its own)"
                    .to_string(),
                hint: HINT_URL.to_string(),
            });
        }
        let Some(host) = parsed.host_str() else {
            return Err(EngineError::Connect {
                message: "the connection url names no host".to_string(),
                hint: HINT_URL.to_string(),
            });
        };
        let port = parsed.port().unwrap_or(if tls { 8443 } else { 8123 });
        // The tunnel's local end replaces host and port and NOTHING else: user,
        // database and the TLS decision ride along unchanged, exactly as the
        // other server engines do it.
        let (host, port) = match &self.host_override {
            Some((h, p)) => (h.clone(), *p),
            None => (host.to_string(), port),
        };
        let user = match parsed.username() {
            "" => "default".to_string(),
            u => percent_decode(u),
        };
        // A password may live in the url's userinfo as well as in `password`;
        // the explicit field wins, like everywhere else in nyet.
        let password = self
            .password
            .clone()
            .or_else(|| parsed.password().map(percent_decode));
        Ok(Endpoint {
            tls,
            authority: format!("{host}:{port}"),
            user,
            password,
            database,
        })
    }

    /// One request, degrading its own parameters exactly as far as the SERVER
    /// makes it — and no further.
    ///
    /// **This is the trap of the engine, and both halves of it were measured on
    /// 24.8 (W9).** A url parameter IS a settings change, and an account already
    /// in readonly mode may not make one:
    ///
    /// - profile `readonly = 1` (the layer-3 setup nyet RECOMMENDS): the caps
    ///   are refused — `Code: 164 ... Cannot modify 'max_execution_time'
    ///   setting in readonly mode` — before a single row is read. The first cut
    ///   of this engine was therefore broken on exactly the hardened account;
    /// - profile `readonly = 2`: even `readonly = 1` itself is refused
    ///   ("Cannot modify 'readonly' setting in readonly mode"), so nyet cannot
    ///   TIGHTEN layer 2 there.
    ///
    /// Hence three attempts, each dropping only what the previous one was told
    /// it may not send:
    ///
    /// 1. `readonly=1` + the caps — what nyet wants, and what every account not
    ///    already in readonly mode accepts (measured: profile 0 takes it, and
    ///    profile 1 takes `readonly=1` because it is the value it already has);
    /// 2. `readonly=1` alone — layer 2 intact, the caps left to the profile;
    /// 3. nothing but `wait_end_of_query`.
    ///
    /// **Step 3 does not silently drop layer 2**, and that is the load-bearing
    /// part: step 2 sends only `readonly` and `wait_end_of_query`, so a settings
    /// refusal there can only be about `readonly` — and ClickHouse refuses to
    /// modify `readonly` only when the session is ALREADY in readonly mode. So
    /// reaching step 3 is the server stating that its own profile carries
    /// readonly 1 or 2. Which of the two it is decides how much layer 2 still
    /// covers, and `nyet doctor`'s `readonly_setting` check reads the profile
    /// and says so — it is not decoration, it is where this fallback is
    /// accounted for.
    ///
    /// Retrying is safe because the refusal happens during SETTINGS validation,
    /// before execution: nothing ran, so nothing is repeated.
    ///
    /// What a degraded request loses is a server-side BOUND, never the read-only
    /// guarantee: the client-side row truncation still marks `truncated`, the
    /// in-process deadline still fires, `MAX_BODY_BYTES` still refuses a reply
    /// too large to hold — and under `readonly = 2`, where the server no longer
    /// refuses table functions, layer 1's denylist is what carries them
    /// (`validator::CLICKHOUSE_DENIED_FUNCTIONS`).
    async fn post(
        &self,
        settings: &[(&str, String)],
        capped: &[(&str, String)],
        sql: &str,
        budget_ms: u64,
    ) -> Result<String, EngineError> {
        // Longest first, so the loop stops at the strongest set the account
        // accepts rather than at the first one that merely works.
        let mut attempts: Vec<Vec<(&str, String)>> = Vec::new();
        if !capped.is_empty() {
            let mut full: Vec<(&str, String)> = settings.to_vec();
            full.extend(capped.iter().cloned());
            attempts.push(full);
        }
        attempts.push(settings.to_vec());
        if settings.iter().any(|(k, _)| *k == "readonly") {
            attempts.push(
                settings
                    .iter()
                    .filter(|(k, _)| *k != "readonly")
                    .cloned()
                    .collect(),
            );
        }
        let last = attempts.len() - 1;
        for (i, attempt) in attempts.into_iter().enumerate() {
            match self.send(&attempt, sql, budget_ms).await {
                Err(EngineError::Db { message, hint }) if i < last => {
                    if !is_settings_refusal(&message) {
                        return Err(EngineError::Db { message, hint });
                    }
                }
                other => return other,
            }
        }
        unreachable!("the loop returns on the last attempt")
    }

    /// One HTTP round trip: the settings nyet forces, then the SQL as the body.
    ///
    /// The SQL is never spliced into the url — ClickHouse reads the request BODY
    /// as the query, so there is no quoting layer between the text the validator
    /// accepted and the text the server parses.
    async fn send(
        &self,
        settings: &[(&str, String)],
        sql: &str,
        budget_ms: u64,
    ) -> Result<String, EngineError> {
        let endpoint = self.endpoint()?;
        let mut query = format!("database={}", encode(&endpoint.database));
        for (k, v) in settings {
            query.push('&');
            query.push_str(k);
            query.push('=');
            query.push_str(&encode(v));
        }
        let uri = format!(
            "{}://{}/?{query}",
            if endpoint.tls { "https" } else { "http" },
            endpoint.authority
        );
        let mut builder = hyper::Request::builder()
            .method("POST")
            .uri(&uri)
            .header("X-ClickHouse-User", &endpoint.user)
            .header("X-ClickHouse-Format", "JSONCompact");
        if let Some(password) = &endpoint.password {
            builder = builder.header("X-ClickHouse-Key", password);
        }
        let request = builder
            .body(http_body_util::Full::new(bytes::Bytes::from(
                sql.as_bytes().to_vec(),
            )))
            .map_err(|_| EngineError::Connect {
                // A header value the http crate rejects — a user name with a
                // newline in it, say. Named as a config problem, never echoed.
                message: "the connection's user name or password cannot be sent in an HTTP \
                          header (it holds a control character)"
                    .to_string(),
                hint: HINT_URL.to_string(),
            })?;
        // rustls needs a process-wide crypto provider, and sqlx installs one of
        // its own when a TLS connection happens first. Installing is idempotent
        // in effect (the second call returns Err and changes nothing), so the
        // result is deliberately ignored: whichever of the two got there first,
        // both are ring.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .build();
        let client: Client<_, http_body_util::Full<bytes::Bytes>> =
            Client::builder(TokioExecutor::new()).build(connector);
        // Two nested bounds, the same shape the sqlx engines use: the connect
        // handshake gets its own generous floor so a blackholed host is
        // CONNECTION_FAILED rather than the outer TIMEOUT, and the whole
        // exchange gets the caller's budget.
        let connect_budget = self
            .connect_timeout_ms
            .map_or_else(|| connect_deadline(budget_ms), Duration::from_millis);
        let deadline = Duration::from_millis(budget_ms).max(connect_budget);
        let response = match tokio::time::timeout(deadline, client.request(request)).await {
            Err(_elapsed) => return Err(client_timeout(budget_ms)),
            Ok(Err(e)) => {
                return Err(EngineError::Connect {
                    // hyper's error text names the host and the OS error, never
                    // the url's userinfo.
                    message: format!("could not reach the ClickHouse HTTP interface: {e}"),
                    hint: "check the host, the port (8123 plain / 8443 TLS) and that the \
                           server's HTTP interface is enabled"
                        .to_string(),
                });
            }
            Ok(Ok(response)) => response,
        };
        let status = response.status();
        // `X-ClickHouse-Exception-Code` is present on a failed reply even when
        // the status is 200 — which happens when the server had already begun
        // streaming. nyet asks for `wait_end_of_query=1` precisely so that
        // cannot happen, and reads the header anyway: a half-written body that
        // parses is the one failure mode a read tool must never report as ok.
        let exception = response
            .headers()
            .get("X-ClickHouse-Exception-Code")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let body = match tokio::time::timeout(deadline, response.into_body().collect()).await {
            Err(_elapsed) => return Err(client_timeout(budget_ms)),
            Ok(Err(e)) => {
                return Err(EngineError::Db {
                    message: format!("the reply from ClickHouse was cut short: {e}"),
                    hint: "retry; if it persists the server may be closing connections early \
                           (check a proxy or load balancer in front of it)"
                        .to_string(),
                })
            }
            Ok(Ok(body)) => body.to_bytes(),
        };
        if body.len() > MAX_BODY_BYTES {
            return Err(EngineError::Db {
                message: format!(
                    "the reply is larger than the {} MiB nyet will hold in memory, so it was \
                     not decoded",
                    MAX_BODY_BYTES / (1024 * 1024)
                ),
                hint: "narrow the query — select fewer columns, or add a WHERE — rather than \
                       lowering the row limit: ClickHouse's row cap does not bound the size of \
                       a single cell"
                    .to_string(),
            });
        }
        let text = String::from_utf8_lossy(&body).into_owned();
        // The third place a failure can hide, and the nastiest. When the reply
        // format is a JSON one — which nyet always asks for — ClickHouse writes
        // the exception INTO the document, as an `"exception"` field beside a
        // perfectly well-formed `"meta": [], "data": [], "rows": 0`. Measured:
        // a refused `CREATE` comes back as valid JSONCompact saying zero rows.
        // The status and the header do catch it here (500 + code 497), and this
        // third check is what makes that not depend on a proxy preserving
        // either one: an empty result that reads as success is the exact failure
        // a read tool must never produce (UX-1).
        if status.is_success() && exception.is_none() && embedded_exception(&text).is_none() {
            return Ok(text);
        }
        Err(server_error(exception.as_deref(), &text))
    }

    /// A query whose reply nyet parses as `JSONCompact`.
    async fn json(
        &self,
        settings: &[(&str, String)],
        capped: &[(&str, String)],
        sql: &str,
        budget_ms: u64,
    ) -> Result<Reply, EngineError> {
        let text = self.post(settings, capped, sql, budget_ms).await?;
        Reply::parse(&text)
    }

    /// The settings nyet forces on EVERY request. Layer 2 lives here.
    ///
    /// `readonly=1` and not `2`: the second one refuses writes but lets a query
    /// raise its own limits (measured — under `readonly=2` a query set
    /// `max_result_rows` to a hundred million and the server obliged), which is
    /// an agent turning off the guard rails nyet just installed.
    /// The parameters nyet sends on EVERY request — the ones an account with
    /// `readonly = 1` in its own profile still accepts (measured: setting
    /// `readonly` to the value it already has is allowed, and
    /// `wait_end_of_query` is an HTTP-interface parameter rather than a query
    /// setting, so `readonly` does not gate it).
    ///
    /// `readonly=1` and not `2`: the second one refuses writes but lets a query
    /// raise its own limits (measured — under `readonly=2` a query set
    /// `max_result_rows` to a hundred million and the server obliged), which is
    /// an agent turning off the guard rails nyet just installed.
    fn base_settings() -> Vec<(&'static str, String)> {
        vec![
            ("readonly", "1".to_string()),
            // Without this the server may answer 200 and start streaming, then
            // hit an error halfway and append the exception text to a body that
            // has already been half-parsed. Buffering the reply server-side
            // makes an error an error.
            ("wait_end_of_query", "1".to_string()),
        ]
    }

    /// The bounds nyet would like the SERVER to enforce. Every one of them is a
    /// real setting, so every one of them is refused outright by an account
    /// whose profile is already `readonly = 1` — see `post`, which is where
    /// that is handled.
    ///
    /// `result_overflow_mode = break` stops the query at a BLOCK boundary once
    /// the row cap is passed, so `max_block_size` is pinned to the same number:
    /// without it the server would still hand over a default 65k-row block for a
    /// ten-row question.
    fn capped_settings(&self, budget_ms: u64, fetch_limit: u64) -> Vec<(&'static str, String)> {
        let limit = fetch_limit.max(1);
        vec![
            (
                "max_execution_time",
                (Self::clamp_statement_timeout(budget_ms) / 1000).to_string(),
            ),
            ("max_result_rows", limit.to_string()),
            ("result_overflow_mode", "break".to_string()),
            ("max_block_size", limit.to_string()),
        ]
    }

    /// The guardrail's number, from `EXPLAIN ESTIMATE`: how many rows the server
    /// expects to READ, from part and mark metadata, without touching a row.
    ///
    /// It answers for MergeTree tables and stays SILENT for everything else —
    /// measured: `system.*` and every table function come back with zero rows.
    /// A silent estimate is `None` (no estimate -> fail open with a warning),
    /// never a zero: reporting "0 rows" for an unestimated monster would be the
    /// guardrail lying, which is worse than the guardrail being absent.
    async fn plan(&self, sql: &str, budget_ms: u64) -> Result<CostEstimate, EngineError> {
        let reply = self
            .json(
                &Self::base_settings(),
                &self.capped_settings(budget_ms.min(ESTIMATE_BUDGET_MS), ESTIMATE_ROW_CAP),
                &format!("EXPLAIN ESTIMATE {sql}"),
                budget_ms,
            )
            .await?;
        let rows = reply.column_index("rows").map(|i| {
            reply
                .rows
                .iter()
                .filter_map(|r| r.get(i).and_then(number_of))
                .sum::<u64>()
        });
        Ok(CostEstimate {
            plan: Value::Array(reply.as_objects()),
            // ClickHouse publishes no planner cost model at all, and nyet does
            // not manufacture one (UX-7).
            cost: None,
            rows: match reply.rows.is_empty() {
                true => None,
                false => rows,
            },
            lower_bound: false,
        })
    }
}

/// How many `EXPLAIN ESTIMATE` rows to read: one per table in the query, so a
/// hundred is already absurd. A cap at all because the estimate goes through the
/// same bounded reader as everything else.
const ESTIMATE_ROW_CAP: u64 = 1_000;

const HINT_URL: &str = "use url = \"http://user@host:8123/dbname\" (or https:// on 8443); the \
                        database name is required, and nyet talks to ClickHouse over its HTTP \
                        interface, not the native protocol";

struct Endpoint {
    tls: bool,
    authority: String,
    user: String,
    password: Option<String>,
    database: String,
}

/// A parsed `JSONCompact` reply: names, types and rows, exactly what the
/// contract needs and nothing the engine has to guess.
struct Reply {
    columns: Vec<String>,
    rows: Vec<Vec<Value>>,
}

/// Is this failure the server saying "this account may not change settings"?
/// Matched on ClickHouse's own wording plus the READONLY code that always
/// accompanies it; `server_error` has already folded the code into the message.
fn is_settings_refusal(message: &str) -> bool {
    message.contains("Cannot modify") && message.contains("in readonly mode")
}

/// ClickHouse serializes 64-bit and wider integers as JSON STRINGS by default,
/// because they do not survive a JavaScript double. nyet's contract says a
/// number is a number, and the obvious fix — asking for
/// `output_format_json_quote_64bit_integers = 0` — is a SETTING, so it is
/// refused on exactly the accounts nyet recommends (see `post`). Reading the
/// declared type instead makes the answer the same shape on every account,
/// which matters more than either spelling: an agent must not have to branch on
/// how the DBA configured the role.
///
/// Scalars only. A wide integer nested inside an `Array(...)`/`Tuple(...)` stays
/// a string — a documented limit rather than a recursive walk over every cell of
/// every reply, and one that no arithmetic in the contract depends on.
fn unquote_wide_integer(ty: &str, value: Value) -> Value {
    let Value::String(text) = &value else {
        return value;
    };
    let base = ty
        .trim_start_matches("LowCardinality(")
        .trim_start_matches("Nullable(");
    let wide = ["Int64", "UInt64", "Int128", "UInt128", "Int256", "UInt256"]
        .iter()
        .any(|w| base.starts_with(w));
    if !wide {
        return value;
    }
    // Through serde_json rather than through i128: the crate is built with
    // `arbitrary_precision`, so a 256-bit integer keeps every digit instead of
    // being rejected or rounded.
    match serde_json::from_str::<Value>(text) {
        Ok(parsed @ Value::Number(_)) => parsed,
        _ => value,
    }
}

impl Reply {
    fn parse(text: &str) -> Result<Reply, EngineError> {
        let malformed = |detail: &str| EngineError::Db {
            message: format!(
                "the ClickHouse reply is not the JSONCompact nyet asked for: {detail}"
            ),
            hint: "this is a server/proxy mismatch rather than a problem with the query — check \
                   whether something in front of ClickHouse rewrites the response"
                .to_string(),
        };
        let value: Value = serde_json::from_str(text).map_err(|e| malformed(&e.to_string()))?;
        let meta = value
            .get("meta")
            .and_then(Value::as_array)
            .ok_or_else(|| malformed("no `meta` array"))?;
        let name_of = |key: &str| {
            meta.iter()
                .map(|column| {
                    column
                        .get(key)
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string()
                })
                .collect::<Vec<String>>()
        };
        let columns = name_of("name");
        let types = name_of("type");
        let rows = value
            .get("data")
            .and_then(Value::as_array)
            .ok_or_else(|| malformed("no `data` array"))?
            .iter()
            .map(|row| {
                row.as_array()
                    .cloned()
                    // A `data` element that is not an array cannot be a row of a
                    // JSONCompact reply; an empty row keeps the shape rather
                    // than dropping a row silently.
                    .unwrap_or_default()
                    .into_iter()
                    .enumerate()
                    .map(|(i, cell)| {
                        unquote_wide_integer(types.get(i).map_or("", String::as_str), cell)
                    })
                    .collect()
            })
            .collect();
        Ok(Reply { columns, rows })
    }

    fn column_index(&self, name: &str) -> Option<usize> {
        self.columns.iter().position(|c| c == name)
    }

    /// The rows as objects keyed by column name — the shape `nyet explain`
    /// publishes for a plan that is a table rather than a tree.
    fn as_objects(&self) -> Vec<Value> {
        self.rows
            .iter()
            .map(|row| {
                let mut object = Map::new();
                for (i, name) in self.columns.iter().enumerate() {
                    object.insert(name.clone(), row.get(i).cloned().unwrap_or(Value::Null));
                }
                Value::Object(object)
            })
            .collect()
    }

    /// One column of one row as text, for the introspection queries.
    fn text(&self, row: usize, column: &str) -> Option<String> {
        let i = self.column_index(column)?;
        match self.rows.get(row)?.get(i)? {
            Value::String(s) => Some(s.clone()),
            Value::Null => None,
            other => Some(other.to_string()),
        }
    }
}

fn number_of(value: &Value) -> Option<u64> {
    match value {
        Value::Number(n) => n.as_u64(),
        // 64-bit integers arrive unquoted (nyet sets
        // output_format_json_quote_64bit_integers=0), but a server that ignores
        // the setting must not silently contribute zero to the guardrail's sum.
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

/// ClickHouse error codes nyet reads by number. The full list is enormous; only
/// the ones that change nyet's BEHAVIOUR are named.
mod code {
    /// `TIMEOUT_EXCEEDED` — the server cancelled on `max_execution_time`.
    pub const TIMEOUT_EXCEEDED: &str = "159";
    /// `TOO_SLOW` — cancelled by `timeout_before_checking_execution_speed`.
    pub const TOO_SLOW: &str = "160";
    /// `READONLY` — layer 2 refused. Reported verbatim: an agent that hits this
    /// has found something layer 1 does not know about, and the message names it.
    pub const READONLY: &str = "164";
    // `ACCESS_DENIED` (497) has no constant here on purpose: the only place it
    // is read is `probe_refusal`, and by then the number is gone — what survives
    // into the message is ClickHouse's own `(ACCESS_DENIED)` suffix.
}

/// Turn a failed ClickHouse reply into the right `EngineError`. The server's own
/// text is echoed because it names the offending token of the CALLER's query —
/// the same reasoning as the sqlparser errors — but trimmed to one line so a
/// stack of context does not land in the agent's window.
fn server_error(exception: Option<&str>, body: &str) -> EngineError {
    let message = first_line(body);
    match exception {
        Some(code::TIMEOUT_EXCEEDED | code::TOO_SLOW) => EngineError::Timeout {
            message: format!("the server cancelled the query on its own time limit: {message}"),
            hint: "narrow the query (WHERE / LIMIT), or raise --timeout or timeout_secs in the \
                   config"
                .to_string(),
        },
        Some(code::READONLY) => EngineError::Db {
            message: format!(
                "the server refused this under readonly = 1, which nyet sets on every request \
                 (layer 2): {message}"
            ),
            hint: "this statement is not a read as far as ClickHouse is concerned — table \
                   functions like url()/file()/s3()/remote() land here too; rewrite it as a \
                   plain SELECT over a table"
                .to_string(),
        },
        _ => EngineError::Db {
            message,
            hint: "check the query against the schema (`nyet schema <alias>`)".to_string(),
        },
    }
}

/// The exception a JSON-formatted reply carries inside the document. `None` for
/// a plain-text error (which ClickHouse sends when the format is not a JSON one)
/// and for a clean reply.
fn embedded_exception(text: &str) -> Option<String> {
    if !text.trim_start().starts_with('{') {
        return None;
    }
    serde_json::from_str::<Value>(text)
        .ok()?
        .get("exception")?
        .as_str()
        .map(str::to_string)
}

/// The message a failed reply carries, wherever ClickHouse put it: inside the
/// JSON document when the format is a JSON one, as the whole body when it is
/// not. Trimmed to the first line, with the trailing build banner dropped —
/// every ClickHouse exception ends in `(version 24.8.14.39 (official build))`,
/// which is noise in every one of them.
fn first_line(text: &str) -> String {
    let text = embedded_exception(text).unwrap_or_else(|| text.to_string());
    let line = text.lines().next().unwrap_or("").trim();
    match line.rfind(" (version ") {
        Some(i) => line[..i].trim().to_string(),
        None => line.to_string(),
    }
}

/// What a FAILED probe CREATE means, from the server's own message. `Some(false)`
/// = `READONLY` (the profile refuses EVERY write, settings included);
/// `Some(true)` = `ACCESS_DENIED` (the GRANTs refuse this DDL — only DDL is
/// proven refused, the same documented DDL-vs-DML gap as PostgreSQL and MySQL);
/// `None` = anything else, which proves nothing and must never read as a pass.
///
/// Matched on the code number nyet already put in the message rather than on
/// English prose: `server_error` prefixes the READONLY case with its own
/// sentence, and the ACCESS_DENIED one arrives verbatim as `Code: 497. ...`.
fn probe_refusal(message: &str) -> Option<bool> {
    if message.contains("readonly = 1") || message.contains("(READONLY)") {
        return Some(false);
    }
    if message.contains("(ACCESS_DENIED)") {
        return Some(true);
    }
    None
}

/// Percent-decoding for the url's userinfo. `url` percent-encodes what it
/// parses, so a password with a `@` or a `/` in it comes back escaped.
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match (bytes[i], bytes.get(i + 1), bytes.get(i + 2)) {
            (b'%', Some(a), Some(b)) => {
                match u8::from_str_radix(&format!("{}{}", *a as char, *b as char), 16) {
                    Ok(byte) => {
                        out.push(byte);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            (byte, _, _) => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Percent-encode a query-string value. Deliberately a strict allowlist of
/// unreserved characters rather than a "escape the dangerous ones" list: a
/// setting value that smuggled a `&` would append a SETTING to the request, and
/// the settings are where layer 2 lives.
fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char);
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

impl Engine for Clickhouse {
    async fn execute(
        &self,
        sql: &str,
        fetch_limit: u64,
        guardrail: &Guardrail,
    ) -> Result<super::QueryOutcome, EngineError> {
        // The guardrail's own request, when there is one to make. It is a
        // SEPARATE HTTP exchange because ClickHouse has no session to share —
        // which also means a failure here cannot leave anything behind.
        let estimate = match guardrail.plans() {
            false => None,
            true => match self
                .plan(sql, ESTIMATE_BUDGET_MS.min(self.query_timeout_ms))
                .await
            {
                Ok(estimate) => {
                    if let Some(value) = guardrail.refuses(&estimate) {
                        return Ok(super::QueryOutcome::Refused { estimate, value });
                    }
                    Some(estimate)
                }
                // Fail OPEN, like the other engines: the server refusing to
                // plan a statement it would happily run is a regression caused
                // purely by the guard. The cli turns `None` into
                // GUARDRAIL_SKIPPED.
                Err(_) => None,
            },
        };
        let reply = self
            .json(
                &Self::base_settings(),
                &self.capped_settings(self.query_timeout_ms, fetch_limit),
                sql,
                self.query_timeout_ms,
            )
            .await?;
        // `result_overflow_mode = break` stops at a block boundary, so the
        // server may hand back a little more than asked; the cli's limit is the
        // contract, so anything at or past the fetch limit is a truncation.
        let truncated = reply.rows.len() as u64 >= fetch_limit;
        let mut rows = reply.rows;
        rows.truncate(fetch_limit as usize);
        Ok(super::QueryOutcome::Ran {
            result: ResultSet {
                // ClickHouse's HTTP interface publishes names and types and NO
                // provenance — there is no `ColumnOrigin` to translate. Net B
                // for this engine is `validator::check_result_names`, applied in
                // the cli's `Db::execute`; these Unknowns are never judged by
                // `check_origins` (which would refuse every query).
                origins: vec![Origin::Unknown; reply.columns.len()],
                columns: reply.columns,
                rows,
                truncated,
            },
            estimate,
        })
    }

    async fn estimate(&self, sql: &str) -> Result<Option<CostEstimate>, EngineError> {
        // `nyet explain` wants the plan a human reads AND the number the
        // guardrail compares, and ClickHouse publishes them through two
        // different EXPLAIN kinds. Neither executes the statement.
        let mut estimate = self.plan(sql, self.query_timeout_ms).await?;
        if let Ok(reply) = self
            .json(
                &Self::base_settings(),
                &self.capped_settings(self.query_timeout_ms, PLAN_ROW_CAP),
                &format!("EXPLAIN {sql}"),
                self.query_timeout_ms,
            )
            .await
        {
            let steps: Vec<Value> = reply
                .rows
                .iter()
                .filter_map(|row| row.first().cloned())
                .collect();
            let mut object = Map::new();
            object.insert("plan".to_string(), Value::Array(steps));
            object.insert("estimate".to_string(), estimate.plan);
            estimate.plan = Value::Object(object);
        }
        Ok(Some(estimate))
    }

    async fn schema(&self, table: Option<&str>) -> Result<Schema, EngineError> {
        let capped = self.capped_settings(self.query_timeout_ms, SCHEMA_ROW_CAP);
        // One request for the objects, one for their columns. `system.tables`
        // and `system.columns` are already filtered by what this role may see,
        // so an unprivileged role gets a short honest answer rather than an
        // error.
        let filter = match table {
            Some(name) => format!("AND name = {}", quote(name)),
            None => String::new(),
        };
        let tables = self
            .json(
                &Self::base_settings(),
                &capped,
                &format!(
                    "SELECT name, engine, sorting_key, primary_key FROM system.tables \
                     WHERE database = currentDatabase() AND NOT is_temporary {filter} \
                     ORDER BY name"
                ),
                self.query_timeout_ms,
            )
            .await?;
        let mut objects: Vec<(String, TableParts)> = Vec::new();
        for i in 0..tables.rows.len() {
            let Some(name) = tables.text(i, "name") else {
                continue;
            };
            let engine = tables.text(i, "engine").unwrap_or_default();
            // ClickHouse calls a view a table with engine `View` /
            // `MaterializedView`; the contract's `kind` is what the agent reads,
            // so the distinction is made here rather than left to the engine name.
            let kind = match engine.as_str() {
                "View" | "MaterializedView" | "LiveView" | "WindowView" => "view",
                _ => "table",
            };
            let mut parts = TableParts::new(kind, true);
            // ClickHouse has no primary key in the relational sense: the sorting
            // key IS the index, and it may repeat values. Publishing it as `pk`
            // would be the first small lie of the answer (UX-7), so it is
            // published as the index it is, under its own name.
            if let Some(sorting) = tables.text(i, "sorting_key").filter(|s| !s.is_empty()) {
                parts.indexes.push(SchemaIndex {
                    name: "ORDER BY".to_string(),
                    columns: sorting
                        .split(',')
                        .map(str::trim)
                        .filter(|c| !c.is_empty())
                        .map(|c| KeyPart::Named(c.to_string()))
                        .collect(),
                    unique: false,
                });
            }
            objects.push((name, parts));
        }
        if objects.is_empty() {
            return Ok(sorted(Vec::new()));
        }
        if over_detail_limit(table, objects.len()) {
            return Ok(listing(objects));
        }
        let columns = self
            .json(
                &Self::base_settings(),
                &capped,
                &format!(
                    "SELECT table, name, type, default_expression FROM system.columns \
                     WHERE database = currentDatabase() {} ORDER BY table, position",
                    match table {
                        Some(name) => format!("AND table = {}", quote(name)),
                        None => String::new(),
                    }
                ),
                self.query_timeout_ms,
            )
            .await?;
        for i in 0..columns.rows.len() {
            let (Some(owner), Some(name)) = (columns.text(i, "table"), columns.text(i, "name"))
            else {
                continue;
            };
            let Some((_, parts)) = objects.iter_mut().find(|(n, _)| *n == owner) else {
                continue;
            };
            let ty = columns.text(i, "type").unwrap_or_default();
            parts.columns.push(SchemaColumn {
                name,
                // ClickHouse types are non-null unless spelled `Nullable(...)`;
                // the type text is the whole answer, so it is read rather than
                // asked for separately.
                nullable: ty.starts_with("Nullable("),
                ty,
                default: columns
                    .text(i, "default_expression")
                    .filter(|d| !d.is_empty()),
                ..SchemaColumn::default()
            });
        }
        Ok(super::assemble(objects))
    }

    /// The probe is the same deliberate hole in layer 2 as everywhere: a write
    /// sent WITHOUT `readonly=1`, so what refuses it is the SERVER and these
    /// credentials, which is what layer 3 means.
    ///
    /// ClickHouse has no transactions, so the PostgreSQL trick (write, roll
    /// back) is not available and this is the MySQL shape: create, then drop,
    /// naming a possible orphan if the drop cannot be confirmed. `ENGINE =
    /// Memory` keeps it off disk.
    async fn diagnose(&self, pii: &[(String, String)]) -> Diagnosis {
        let budget = self.query_timeout_ms;
        // Connectivity first, and without layer 2 removed: a plain read.
        if let Err(e) = self
            .json(&Self::base_settings(), &[], "SELECT 1", budget)
            .await
        {
            let (message, hint) = error_parts(e);
            return Diagnosis {
                connect: ConnectFact::Failed { message, hint },
                server: None,
                pii: Vec::new(),
                pii_views: None,
            };
        }
        let readonly = self.readonly_profile(budget).await;
        let probe = self.write_probe(budget).await;
        let superuser = self.superuser(budget).await;
        Diagnosis {
            connect: ConnectFact::Ok {
                via_tunnel: self.host_override.is_some(),
            },
            server: Some(ServerFacts {
                superuser,
                read_only_note: None,
                probe,
                js: None,
                readonly: Some(readonly),
                classifier_error: None,
            }),
            pii: self.pii_access(pii, budget).await,
            // A `[pii]` rule names a table, and a view over it is outside the
            // policy — the same gap PostgreSQL's check reports. ClickHouse
            // publishes each view's definition text in `system.tables`, so the
            // question is answerable.
            pii_views: match pii.is_empty() {
                true => None,
                false => self.pii_views(pii, budget).await,
            },
        }
    }
}

/// How many `EXPLAIN` steps to read for `nyet explain`, and how many catalog
/// rows `nyet schema` may pull. Both are bounds on nyet's own memory, not
/// policy: a schema wider than this is already past the detail limit.
const PLAN_ROW_CAP: u64 = 1_000;
const SCHEMA_ROW_CAP: u64 = 100_000;

/// A string literal for a ClickHouse query. Only ever wraps names that came
/// from the AGENT's `[table]` argument, which is why it exists at all: doubling
/// the quote is what keeps a name with an apostrophe from becoming syntax.
fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\\', "\\\\").replace('\'', "\\'"))
}

impl Clickhouse {
    /// The `readonly` setting the ROLE'S OWN profile carries — read on a
    /// request that does NOT set it, so what comes back is the server's answer
    /// rather than nyet's own parameter echoed back.
    async fn readonly_profile(&self, budget_ms: u64) -> ReadonlyFact {
        // Deliberately NOT `base_settings`: that one sets readonly=1, and asking
        // "what is readonly?" through a request that just set it would report
        // nyet's own parameter back as the profile's value. Nothing else is sent
        // either — every real setting is refused outright by the very profile
        // this is trying to read.
        match self
            .json(
                &[("wait_end_of_query", "1".to_string())],
                &[],
                "SELECT value FROM system.settings WHERE name = 'readonly'",
                budget_ms,
            )
            .await
        {
            Ok(reply) => match reply.text(0, "value").as_deref() {
                Some("0") => ReadonlyFact::Profile(0),
                Some("1") => ReadonlyFact::Profile(1),
                Some("2") => ReadonlyFact::Profile(2),
                other => ReadonlyFact::Unknown(format!(
                    "the server reported readonly = {}, which nyet does not recognise",
                    other.unwrap_or("nothing")
                )),
            },
            Err(e) => {
                let (detail, _) = error_parts(e);
                ReadonlyFact::Unknown(detail)
            }
        }
    }

    /// Create then drop a throwaway table WITHOUT layer 2, so the refusal (or
    /// the lack of one) is the server's verdict on these credentials.
    async fn write_probe(&self, budget_ms: u64) -> ProbeFact {
        let name = probe_name();
        // No `readonly` here on purpose — this is the one place layer 2 is
        // removed, so that what refuses the CREATE is the server's verdict on
        // these credentials. No `max_execution_time` either, and that one is
        // load-bearing: an account whose profile is readonly = 1 would refuse
        // the SETTING, and `probe_refusal` would read that READONLY as proof
        // that the WRITE was refused — a false ok, on the exact setup nyet
        // recommends. The in-process deadline below is the bound instead.
        let settings = vec![("wait_end_of_query", "1".to_string())];
        let create = format!("CREATE TABLE {name} (a UInt8) ENGINE = Memory");
        match self.post(&settings, &[], &create, budget_ms).await {
            Err(EngineError::Db { message, .. }) => match probe_refusal(&message) {
                Some(ddl_only) => ProbeFact::Blocked {
                    detail: message,
                    ddl_only,
                },
                None => ProbeFact::Unknown { detail: message },
            },
            // A timeout or a transport failure: the CREATE may or may not have
            // taken effect, so the possible orphan is named rather than assumed
            // away (the MySQL wording, for the same reason).
            Err(e) => {
                let (detail, _) = error_parts(e);
                ProbeFact::Unknown {
                    detail: format!(
                        "{detail} (the probe table `{name}` may have been created — check for it \
                         and DROP it if it is there)"
                    ),
                }
            }
            Ok(_) => {
                let dropped = self
                    .post(&settings, &[], &format!("DROP TABLE {name}"), budget_ms)
                    .await
                    .is_ok();
                ProbeFact::Wrote {
                    orphan: (!dropped).then(|| name.clone()),
                }
            }
        }
    }

    /// Does this account hold ClickHouse's own everything-grant? `SHOW GRANTS`
    /// answers for the CURRENT user without needing access management rights,
    /// which is exactly the account nyet wants to describe.
    async fn superuser(&self, budget_ms: u64) -> SuperuserFact {
        match self
            .json(&Self::base_settings(), &[], "SHOW GRANTS", budget_ms)
            .await
        {
            Err(e) => {
                let (detail, _) = error_parts(e);
                SuperuserFact::Unknown(detail)
            }
            Ok(reply) => {
                let lines: Vec<String> = (0..reply.rows.len())
                    .filter_map(|i| reply.rows[i].first().and_then(Value::as_str))
                    .map(str::to_string)
                    .collect();
                // `GRANT ALL ON *.*` is ClickHouse's superuser, and
                // ACCESS MANAGEMENT is the half of it that can hand itself
                // more — either one is a finding.
                let wide = lines.iter().find(|l| {
                    let upper = l.to_uppercase();
                    (upper.contains("GRANT ALL") && upper.contains("ON *.*"))
                        || upper.contains("ACCESS MANAGEMENT")
                });
                match wide {
                    Some(line) => SuperuserFact::Yes(format!(
                        "this account holds a cluster-wide grant: {line}"
                    )),
                    None if lines.is_empty() => SuperuserFact::Unknown(
                        "the server listed no grants for this account at all".to_string(),
                    ),
                    None => SuperuserFact::No(format!(
                        "this account holds {} scoped grant(s) and no ALL/ACCESS MANAGEMENT",
                        lines.len()
                    )),
                }
            }
        }
    }

    /// Can this role read each protected column? ClickHouse grants reach column
    /// level (`GRANT SELECT(a, b) ON db.t`), so the question has a real answer:
    /// `system.columns` lists only the columns the current role may see.
    async fn pii_access(&self, pii: &[(String, String)], budget_ms: u64) -> Vec<PiiAccess> {
        if pii.is_empty() {
            return Vec::new();
        }
        let visible = self
            .json(
                &Self::base_settings(),
                &self.capped_settings(budget_ms, SCHEMA_ROW_CAP),
                "SELECT table, name FROM system.columns WHERE database = currentDatabase()",
                budget_ms,
            )
            .await
            .ok();
        pii.iter()
            .map(|(table, column)| PiiAccess {
                column: format!("{table}.{column}"),
                readable: visible.as_ref().map(|reply| {
                    (0..reply.rows.len()).any(|i| {
                        reply
                            .text(i, "table")
                            .is_some_and(|t| t.eq_ignore_ascii_case(table))
                            && reply
                                .text(i, "name")
                                .is_some_and(|c| c.eq_ignore_ascii_case(column))
                    })
                }),
            })
            .collect()
    }

    /// Views whose DEFINITION reads a protected table. `system.tables` publishes
    /// `create_table_query` for every object this role can see, so the answer is
    /// one request — and it is a TEXT match, which is why the check's wording
    /// promises exactly that and no more.
    async fn pii_views(&self, pii: &[(String, String)], budget_ms: u64) -> Option<Vec<String>> {
        let reply = self
            .json(
                &Self::base_settings(),
                &self.capped_settings(budget_ms, SCHEMA_ROW_CAP),
                "SELECT name, create_table_query FROM system.tables \
                 WHERE database = currentDatabase() AND engine LIKE '%View' ORDER BY name",
                budget_ms,
            )
            .await
            .ok()?;
        let mut out = Vec::new();
        for i in 0..reply.rows.len() {
            let (Some(name), Some(sql)) =
                (reply.text(i, "name"), reply.text(i, "create_table_query"))
            else {
                continue;
            };
            let lower = sql.to_lowercase();
            if pii
                .iter()
                .any(|(table, column)| lower.contains(table) && lower.contains(column))
            {
                out.push(name);
            }
        }
        Some(out)
    }
}
