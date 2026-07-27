//! MongoDB layer 1: a parser for a **subset of the mongosh syntax** plus a
//! closed allowlist over what it parsed. Pure (Д1/Д2) — it depends only on
//! `mongodb::bson` (+std), does no IO, and the golden corpus in
//! `tests/corpus/mongo/` runs it without a live server.
//!
//! Two responsibilities, deliberately separate:
//!
//! 1. **[`parse`]** turns the agent's text into a typed [`Request`]. It accepts
//!    exactly the shapes listed in `ALLOWED_METHODS`/`ALLOWED_CHAIN`; anything
//!    else — a method it does not know, an argument it cannot read, a stray
//!    token — is a refusal, never a "let's send it and see". Д3: the text is
//!    untrusted input, so there is no `unwrap`, no panic and an explicit depth
//!    limit on every recursion.
//! 2. **[`classify`]** walks the whole parsed document and refuses any `$`-key
//!    that is not on the allowlist — at every nesting level, in every position.
//!    That is the security property: a write/JS/Atlas/internal operator added by
//!    a future MongoDB major is refused *by default*, because it is not on a
//!    list we wrote.
//!
//! There is no layer 2 here (MongoDB has no read-only session — see
//! docs/DEV.md), so this module is the only thing between the agent and the
//! server other than the credentials' own privileges (layer 3).

/// Reading the server's METADATA replies (schema/explain/doctor). Split out on
/// purpose: this file is the security boundary and stays about the boundary,
/// while `meta` is about presenting what the server said. Both are pure.
pub mod meta;

use mongodb::bson::{Bson, Decimal128, Document, Regex};
use std::str::FromStr;

/// `error.reason` values this module can produce. Shared spellings with the SQL
/// validator (`PARSE_FAILED`, `WRITE_OPERATION`, `DENIED_FUNCTION`) mean exactly
/// what they mean there — a unit test pins that they stay identical strings.
/// `DENIED_COMMAND` and `DENIED_OPERATOR` are new (append-only, Д7).
pub const PARSE_FAILED: &str = "PARSE_FAILED";
pub const WRITE_OPERATION: &str = "WRITE_OPERATION";
pub const DENIED_FUNCTION: &str = "DENIED_FUNCTION";
/// The collection method (`db.c.<method>(...)`) is not on the read allowlist.
pub const DENIED_COMMAND: &str = "DENIED_COMMAND";
/// A `$`-prefixed key (stage, query operator, aggregation expression,
/// accumulator) is not on the read allowlist, or is a service field nyet owns.
pub const DENIED_OPERATOR: &str = "DENIED_OPERATOR";

/// One refusal, ready for the cli's NYET envelope (exit 5).
#[derive(Debug)]
pub struct Refusal {
    pub reason: &'static str,
    pub message: String,
    pub hint: String,
}

fn refuse<T>(
    reason: &'static str,
    message: impl Into<String>,
    hint: impl Into<String>,
) -> Result<T, Refusal> {
    Err(Refusal {
        reason,
        message: message.into(),
        hint: hint.into(),
    })
}

/// The generic hint for a syntax refusal (Д10: what happened -> why -> what to
/// do instead). Every parse refusal ends here, so the agent always learns the
/// accepted shape.
fn syntax_hint() -> String {
    "nyet accepts a subset of the mongosh read syntax: \
     db.<collection>.find(<filter>[, <projection>])[.sort({..})][.skip(n)][.limit(n)], \
     .findOne(<filter>[, <projection>]), .aggregate([<stages>]), \
     .countDocuments(<filter>), .distinct(\"<field>\"[, <filter>]) — \
     values are JSON plus ObjectId(\"..\"), ISODate(\"..\"), NumberLong(..), \
     NumberInt(..), NumberDecimal(\"..\"), UUID(\"..\") and /regex/i"
        .to_string()
}

/// What nyet will send to the server, once it has been parsed AND classified.
#[derive(Debug, PartialEq)]
pub struct Request {
    pub collection: String,
    pub op: Op,
}

#[derive(Debug, PartialEq)]
pub enum Op {
    Find {
        filter: Document,
        projection: Option<Document>,
        sort: Option<Document>,
        skip: Option<i64>,
        /// The agent's own `.limit(n)` (or 1 for `findOne`), if any. The
        /// effective limit is `min(this, nyet's fetch limit)`.
        limit: Option<i64>,
    },
    Aggregate {
        pipeline: Vec<Bson>,
    },
    /// `countDocuments` — an aggregation, exactly like mongosh's own
    /// implementation (the legacy `count` command is inaccurate on a sharded
    /// or unclean shutdown).
    Count {
        filter: Document,
    },
    Distinct {
        key: String,
        filter: Document,
    },
}

// ---------------------------------------------------------------------------
// The allowlists. Everything here is READ-ONLY by construction: nothing that
// writes, evaluates server-side JavaScript, opens an unbounded cursor, reads
// cluster state or belongs to Atlas is on any of these lists — and because they
// are ALLOWlists, an operator introduced by a future MongoDB release is refused
// until someone adds it here on purpose.
// ---------------------------------------------------------------------------

/// Collection methods nyet knows how to run as a read.
const ALLOWED_METHODS: &[&str] = &["aggregate", "countDocuments", "distinct", "find", "findOne"];

/// Methods that WRITE. They are refused by the allowlist above anyway; naming
/// them buys the sharper `WRITE_OPERATION` reason and a message that says so.
const WRITE_METHODS: &[&str] = &[
    "bulkWrite",
    "createIndex",
    "createIndexes",
    "deleteMany",
    "deleteOne",
    "drop",
    "dropIndex",
    "dropIndexes",
    "findAndModify",
    "findOneAndDelete",
    "findOneAndReplace",
    "findOneAndUpdate",
    "insert",
    "insertMany",
    "insertOne",
    "remove",
    "renameCollection",
    "replaceOne",
    "save",
    "update",
    "updateMany",
    "updateOne",
];

/// Methods that run server-side JavaScript. Same story as `WRITE_METHODS`:
/// already refused, named only for the honest reason (`DENIED_FUNCTION`).
const JS_METHODS: &[&str] = &["mapReduce"];

/// Cursor methods accepted after `find` (mongosh allows them on a FindCursor).
/// `toArray` is a no-op for nyet (the result is materialized either way) and is
/// accepted because it is how mongosh users habitually end a query.
const ALLOWED_CHAIN: &[&str] = &["limit", "skip", "sort", "toArray"];

/// Aggregation pipeline stages that only READ. Sorted — `is_allowed` binary
/// searches, and `lists_are_sorted` pins it.
///
/// Deliberately absent, each for a stated reason (docs/DEV.md):
/// `$out`/`$merge` (write), `$where`/`$function`/`$accumulator` (server JS),
/// `$changeStream` (an unbounded cursor that would hang the CLI),
/// `$search`/`$vectorSearch` (Atlas-only sub-languages nyet cannot classify),
/// `$currentOp`/`$listLocalSessions`/`$listSessions`/`$planCacheStats`/
/// `$listCatalog`/`$collStats`/`$indexStats`/`$shardedDataDistribution`
/// (cluster introspection — other sessions' query text can quote real data),
/// and every `$_internal*` stage (undocumented, ~30 of them, growing per
/// release, and at least one of them WRITES under the plain `read` role).
/// Which of the stages above name a collection BESIDES the one the query
/// names. Kept here, next to `STAGES`, on purpose: adding a stage that takes a
/// namespace means adding it here too, and `check_collection_source` (which
/// keeps `system.*` and other databases out of them) reads this list.
const NAMESPACE_STAGES: &[&str] = &["$graphLookup", "$lookup", "$unionWith"];

const STAGES: &[&str] = &[
    "$addFields",
    "$bucket",
    "$bucketAuto",
    "$count",
    "$densify",
    "$facet",
    "$fill",
    "$graphLookup",
    "$group",
    "$limit",
    "$lookup",
    "$match",
    "$project",
    "$redact",
    "$replaceRoot",
    "$replaceWith",
    "$sample",
    "$set",
    "$setWindowFields",
    "$skip",
    "$sort",
    "$sortByCount",
    "$unionWith",
    "$unset",
    "$unwind",
];

/// Query operators, aggregation-expression operators, accumulators and window
/// operators — ONE union list, applied to every `$`-key outside stage position.
///
/// The union is deliberate: splitting it per position would buy precision nyet
/// does not need (using `$sum` in a filter is a *server* error, not a security
/// hole) at the cost of a much larger rule surface that could drift. What the
/// union must never contain is anything that writes, evaluates JavaScript or
/// reaches outside the collection — and it does not.
const OPS: &[&str] = &[
    "$abs",
    "$add",
    "$addToSet",
    "$all",
    "$allElementsTrue",
    "$and",
    "$anyElementTrue",
    "$arrayElemAt",
    "$arrayToObject",
    "$avg",
    "$binarySize",
    "$bitsAllClear",
    "$bitsAllSet",
    "$bitsAnyClear",
    "$bitsAnySet",
    "$bottom",
    "$bottomN",
    "$bsonSize",
    "$ceil",
    "$cmp",
    "$concat",
    "$concatArrays",
    "$cond",
    "$convert",
    "$count",
    "$covariancePop",
    "$covarianceSamp",
    "$dateAdd",
    "$dateDiff",
    "$dateFromParts",
    "$dateFromString",
    "$dateSubtract",
    "$dateToParts",
    "$dateToString",
    "$dateTrunc",
    "$dayOfMonth",
    "$dayOfWeek",
    "$dayOfYear",
    "$denseRank",
    "$derivative",
    "$divide",
    "$documentNumber",
    "$elemMatch",
    "$eq",
    "$exists",
    "$exp",
    "$expMovingAvg",
    "$expr",
    "$filter",
    "$first",
    "$firstN",
    "$floor",
    "$getField",
    "$gt",
    "$gte",
    "$hour",
    "$ifNull",
    "$in",
    "$indexOfArray",
    "$indexOfBytes",
    "$indexOfCP",
    "$integral",
    "$isArray",
    "$isNumber",
    "$isoDayOfWeek",
    "$isoWeek",
    "$isoWeekYear",
    "$last",
    "$lastN",
    "$let",
    "$linearFill",
    "$literal",
    "$ln",
    "$locf",
    "$log",
    "$log10",
    "$lt",
    "$lte",
    "$ltrim",
    "$map",
    "$max",
    "$maxN",
    "$median",
    "$mergeObjects",
    "$millisecond",
    "$min",
    "$minN",
    "$minute",
    "$mod",
    "$month",
    "$multiply",
    "$ne",
    "$nin",
    "$nor",
    "$not",
    "$objectToArray",
    "$options",
    "$or",
    "$percentile",
    "$pow",
    "$push",
    "$range",
    "$rank",
    "$reduce",
    "$regex",
    "$regexFind",
    "$regexFindAll",
    "$regexMatch",
    "$replaceAll",
    "$replaceOne",
    "$reverseArray",
    "$round",
    "$rtrim",
    "$second",
    "$setDifference",
    "$setEquals",
    "$setIntersection",
    "$setIsSubset",
    "$setUnion",
    "$shift",
    "$size",
    "$slice",
    "$sortArray",
    "$split",
    "$sqrt",
    "$stdDevPop",
    "$stdDevSamp",
    "$strLenBytes",
    "$strLenCP",
    "$strcasecmp",
    "$substr",
    "$substrBytes",
    "$substrCP",
    "$subtract",
    "$sum",
    "$switch",
    "$toBool",
    "$toDate",
    "$toDecimal",
    "$toDouble",
    "$toInt",
    "$toLong",
    "$toLower",
    "$toObjectId",
    "$toString",
    "$toUpper",
    "$top",
    "$topN",
    "$trim",
    "$trunc",
    "$type",
    "$week",
    "$year",
    "$zip",
];

/// Keys that WRITE. Refused wherever they appear — including nested pipelines,
/// where the server would refuse them too, and where it would not.
const WRITE_KEYS: &[&str] = &["$merge", "$out"];

/// Keys that make the SERVER evaluate JavaScript. Never on any allowlist:
/// they run arbitrary code inside the database process, they are not covered by
/// `maxTimeMS` (measured), and no read needs them.
const JS_KEYS: &[&str] = &["$accumulator", "$function", "$where"];

/// Service fields nyet owns or refuses. They cannot appear in the mongosh
/// subset (nyet builds the command document itself), but a `$`-spelled one
/// inside a filter would be caught by the allowlist anyway; this list only
/// sharpens the message for the ones an agent is likely to try.
const NYET_OWNED: &[&str] = &["$comment", "$db", "$hint", "$maxTimeMS", "$readPreference"];

fn is_listed(list: &[&str], name: &str) -> bool {
    list.binary_search(&name).is_ok()
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Layer 1 for MongoDB: parse, then classify. Pure and deterministic — the cli
/// calls it to refuse before connecting, and the engine calls it again on the
/// same text to get the request it executes, so what runs is always what was
/// classified (no validate/exec drift).
pub fn check(text: &str) -> Result<Request, Refusal> {
    let request = parse(text)?;
    classify(&request)?;
    Ok(request)
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// Hard ceiling on nesting, for BOTH the parser and the classifier. The parser
/// recurses per `{`/`[`/`(`, so without it a few thousand braces would overflow
/// the stack — an abort, which is not a refusal (Д3). Set to MongoDB's own BSON
/// nesting limit, so nyet refuses exactly what the server would and no
/// legitimate document is caught by it.
const MAX_DEPTH: usize = 100;

/// Hard ceiling on the input, so a multi-megabyte argv cannot turn into
/// quadratic work or an enormous command document. Counted in BYTES and
/// checked BEFORE the text is expanded into a `Vec<char>` — a char count let
/// four-byte characters through at four times the advertised size, and it
/// allocated the vector before deciding.
const MAX_INPUT_BYTES: usize = 64 * 1024;

struct Parser {
    chars: Vec<char>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn peek_at(&self, ahead: usize) -> Option<char> {
        self.chars.get(self.pos + ahead).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek();
        if c.is_some() {
            self.pos += 1;
        }
        c
    }

    fn at(&self, c: char) -> bool {
        self.peek() == Some(c)
    }

    /// Whitespace and JS comments (`//...`, `/* ... */`). A `/` that starts a
    /// regex literal is never consumed here: a regex cannot begin with `/` or
    /// `*`, so the two-character lookahead decides unambiguously.
    fn skip_ws(&mut self) -> Result<(), Refusal> {
        loop {
            match self.peek() {
                Some(c) if c.is_whitespace() => {
                    self.pos += 1;
                }
                Some('/') if self.peek_at(1) == Some('/') => {
                    while let Some(c) = self.peek() {
                        if c == '\n' {
                            break;
                        }
                        self.pos += 1;
                    }
                }
                Some('/') if self.peek_at(1) == Some('*') => {
                    self.pos += 2;
                    loop {
                        match self.peek() {
                            None => {
                                return refuse(
                                    PARSE_FAILED,
                                    "nyet: unterminated /* comment in the query",
                                    syntax_hint(),
                                )
                            }
                            Some('*') if self.peek_at(1) == Some('/') => {
                                self.pos += 2;
                                break;
                            }
                            Some(_) => self.pos += 1,
                        }
                    }
                }
                _ => return Ok(()),
            }
        }
    }

    fn expect(&mut self, c: char, what: &str) -> Result<(), Refusal> {
        self.skip_ws()?;
        if self.at(c) {
            self.pos += 1;
            return Ok(());
        }
        refuse(
            PARSE_FAILED,
            format!(
                "nyet: expected '{c}' {what} at position {}, found {}",
                self.pos,
                self.describe_here()
            ),
            syntax_hint(),
        )
    }

    /// What sits at the cursor, for an error message. Never echoes more than a
    /// few characters of the input.
    fn describe_here(&self) -> String {
        match self.peek() {
            None => "end of input".to_string(),
            Some(c) => format!("'{c}'"),
        }
    }

    /// A bare identifier: `[A-Za-z_$][A-Za-z0-9_$]*`, the JS rule for an
    /// unquoted object key or a method name.
    fn ident(&mut self) -> String {
        let start = self.pos;
        if self
            .peek()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_' || c == '$')
        {
            self.pos += 1;
            while self
                .peek()
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
            {
                self.pos += 1;
            }
        }
        self.chars[start..self.pos].iter().collect()
    }

    /// One segment of `db.<a>.<b>...`: a collection name may hold characters an
    /// identifier may not (`-`), so this is looser than `ident` on purpose. The
    /// dot itself is the separator and is never part of a segment.
    fn segment(&mut self) -> String {
        let start = self.pos;
        while self
            .peek()
            .is_some_and(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '+' | '@'))
        {
            self.pos += 1;
        }
        self.chars[start..self.pos].iter().collect()
    }
}

/// Parse the mongosh subset. Every failure is a refusal with an actionable
/// hint; no input can panic (Д3).
pub fn parse(text: &str) -> Result<Request, Refusal> {
    if text.len() > MAX_INPUT_BYTES {
        return refuse(
            PARSE_FAILED,
            format!(
                "nyet: the query is {} bytes, over nyet's {MAX_INPUT_BYTES}-byte limit",
                text.len()
            ),
            "send a shorter query; a filter that large is usually an inlined list that \
             belongs in the database (or in a narrower $match)",
        );
    }
    let mut p = Parser {
        chars: text.chars().collect(),
        pos: 0,
    };
    p.skip_ws()?;
    if p.ident() != "db" {
        return refuse(
            PARSE_FAILED,
            "nyet: a MongoDB query must start with `db.`",
            syntax_hint(),
        );
    }

    // db.<segment>.<segment>...( — the LAST segment before '(' is the method,
    // everything before it is the collection (MongoDB collection names may
    // contain dots, e.g. `orders.archive`).
    let mut segments: Vec<String> = Vec::new();
    loop {
        p.expect('.', "after the collection name")?;
        p.skip_ws()?;
        let seg = p.segment();
        if seg.is_empty() {
            return refuse(
                PARSE_FAILED,
                format!(
                    "nyet: expected a collection or method name after '.', found {}",
                    p.describe_here()
                ),
                syntax_hint(),
            );
        }
        segments.push(seg);
        p.skip_ws()?;
        if p.at('(') {
            break;
        }
        if !p.at('.') {
            return refuse(
                PARSE_FAILED,
                format!(
                    "nyet: expected '.' or '(' after '{}', found {}",
                    segments.last().cloned().unwrap_or_default(),
                    p.describe_here()
                ),
                syntax_hint(),
            );
        }
    }
    let method = segments.pop().unwrap_or_default();
    if segments.is_empty() {
        // `db.runCommand(...)`, `db.adminCommand(...)`, `db.getSiblingDB(...)`:
        // database-level commands, which are not a read of a collection and are
        // exactly how one would reach the write/admin surface.
        return refuse(
            DENIED_COMMAND,
            format!(
                "nyet: `db.{method}(...)` is a database-level command, and nyet only runs \
                 reads of one collection"
            ),
            format!(
                "name the collection: db.<collection>.find(...) / .aggregate([...]) / \
                 .countDocuments(...) / .distinct(...); `db.{method}` has no read-only \
                 form nyet can guarantee"
            ),
        );
    }
    let collection = segments.join(".");
    check_collection_name(&collection)?;

    // The METHOD is judged before its arguments are even read: a write is a
    // write whatever it was handed, and a syntax error inside the arguments
    // must not turn `insertOne(<garbage>)` into a mere PARSE_FAILED.
    check_method(&method)?;
    let args = parse_args(&mut p, 0)?;
    let mut op = build_op(&method, args)?;

    // Cursor methods: .sort({..}).skip(n).limit(n).toArray()
    loop {
        p.skip_ws()?;
        if !p.at('.') {
            break;
        }
        p.pos += 1;
        p.skip_ws()?;
        let name = p.ident();
        // Same rule as the method: the name decides first, so `.forEach(...)`
        // is refused as a method nyet does not run rather than as unparseable
        // JavaScript.
        check_chain(&name)?;
        let args = parse_args(&mut p, 0)?;
        apply_chain(&mut op, &name, args)?;
    }

    p.skip_ws()?;
    if p.at(';') {
        p.pos += 1;
        p.skip_ws()?;
    }
    if p.peek().is_some() {
        return refuse(
            PARSE_FAILED,
            format!(
                "nyet: unexpected {} after the end of the query",
                p.describe_here()
            ),
            "send exactly one statement; nyet runs one read per call",
        );
    }
    Ok(Request { collection, op })
}

/// `( [value {, value}] [,] )` — the argument list of a method, a chain call or
/// a type constructor. `depth` is threaded through so a chain of constructors
/// (`NumberLong(NumberLong(...))`) is bounded by the same limit as a chain of
/// braces: without it the recursion would restart at zero on every `(`.
fn parse_args(p: &mut Parser, depth: usize) -> Result<Vec<Bson>, Refusal> {
    if depth > MAX_DEPTH {
        return too_deep();
    }
    p.expect('(', "to open the arguments")?;
    let mut args = Vec::new();
    loop {
        p.skip_ws()?;
        if p.at(')') {
            p.pos += 1;
            return Ok(args);
        }
        if !args.is_empty() {
            return refuse(
                PARSE_FAILED,
                format!(
                    "nyet: expected ',' or ')' in the argument list, found {}",
                    p.describe_here()
                ),
                syntax_hint(),
            );
        }
        loop {
            args.push(parse_value(p, depth + 1)?);
            p.skip_ws()?;
            if p.at(',') {
                p.pos += 1;
                p.skip_ws()?;
                // Trailing comma before ')'.
                if p.at(')') {
                    break;
                }
                continue;
            }
            break;
        }
    }
}

/// One method call -> the typed operation, with strict arity. An option
/// document (mongosh's second `aggregate` argument, or `find`'s third) is
/// refused here rather than sanitized: `allowDiskUse`, `let`, `readConcern`,
/// `comment`, `bypassDocumentValidation`, `lsid` and friends are command-level
/// switches that nyet owns, and accepting a document of them would mean
/// maintaining a second allowlist for something no read needs.
fn check_method(method: &str) -> Result<(), Refusal> {
    if is_listed(WRITE_METHODS, method) {
        return refuse(
            WRITE_OPERATION,
            format!("nyet: `{method}` writes to the database"),
            "nyet is read-only: use find / findOne / aggregate / countDocuments / distinct; \
             nothing nyet can run modifies data",
        );
    }
    if is_listed(JS_METHODS, method) {
        return refuse(
            DENIED_FUNCTION,
            format!(
                "nyet: `{method}` runs JavaScript inside the database server, and it can \
                 write its output to a collection"
            ),
            "express the same computation as an aggregation pipeline \
             (db.<collection>.aggregate([{ $group: ... }])) — server-side JavaScript is \
             never allowed, so $where / $function / $accumulator are refused too",
        );
    }
    if !is_listed(ALLOWED_METHODS, method) {
        return refuse(
            DENIED_COMMAND,
            format!("nyet: `{method}` is not on nyet's read allowlist for MongoDB"),
            format!(
                "allowed methods: {}; anything else is refused by default, including \
                 methods a newer MongoDB adds",
                ALLOWED_METHODS.join(", ")
            ),
        );
    }
    Ok(())
}

fn check_chain(name: &str) -> Result<(), Refusal> {
    if is_listed(ALLOWED_CHAIN, name) {
        return Ok(());
    }
    refuse(
        DENIED_COMMAND,
        format!("nyet: the cursor method `.{name}()` is not on nyet's read allowlist"),
        format!(
            "allowed after find(): {}; ordering and paging belong in .sort()/.skip()/\
             .limit(), and the result is always materialized by nyet",
            ALLOWED_CHAIN.join(", ")
        ),
    )
}

/// Shape and arity, once the method name is known to be a read.
fn build_op(method: &str, mut args: Vec<Bson>) -> Result<Op, Refusal> {
    let arity = |max: usize| -> Result<(), Refusal> {
        if args.len() > max {
            return refuse(
                DENIED_COMMAND,
                format!(
                    "nyet: `{method}` takes at most {max} argument(s) here, got {}",
                    args.len()
                ),
                "nyet builds the command options itself (limit, batch size, maxTimeMS), so \
                 an options document — allowDiskUse, let, readConcern, comment, \
                 bypassDocumentValidation and the rest — is not accepted; put the query in \
                 the filter/pipeline instead",
            );
        }
        Ok(())
    };
    let doc_arg = |arg: Option<Bson>, what: &str| -> Result<Option<Document>, Refusal> {
        match arg {
            None => Ok(None),
            Some(Bson::Document(d)) => Ok(Some(d)),
            Some(_) => refuse(
                PARSE_FAILED,
                format!("nyet: the {what} argument of `{method}` must be a document"),
                syntax_hint(),
            ),
        }
    };

    match method {
        "find" | "findOne" => {
            arity(2)?;
            let mut it = args.into_iter();
            let filter = doc_arg(it.next(), "filter")?.unwrap_or_default();
            let projection = doc_arg(it.next(), "projection")?;
            Ok(Op::Find {
                filter,
                projection,
                sort: None,
                skip: None,
                limit: (method == "findOne").then_some(1),
            })
        }
        "aggregate" => {
            arity(1)?;
            match args.pop() {
                Some(Bson::Array(pipeline)) => Ok(Op::Aggregate { pipeline }),
                _ => refuse(
                    PARSE_FAILED,
                    "nyet: `aggregate` takes one argument: an array of pipeline stages",
                    "write it as db.<collection>.aggregate([{ $match: {...} }, { $group: {...} }]); \
                     the mongosh form that spreads stages as separate arguments is not accepted",
                ),
            }
        }
        "countDocuments" => {
            arity(1)?;
            let filter = doc_arg(args.pop(), "filter")?.unwrap_or_default();
            Ok(Op::Count { filter })
        }
        "distinct" => {
            arity(2)?;
            let mut it = args.into_iter();
            let key = match it.next() {
                Some(Bson::String(s)) if !s.is_empty() => s,
                _ => {
                    return refuse(
                        PARSE_FAILED,
                        "nyet: `distinct` needs a field name as its first argument",
                        "write it as db.<collection>.distinct(\"status\") or \
                         db.<collection>.distinct(\"status\", { active: true })",
                    )
                }
            };
            let filter = doc_arg(it.next(), "filter")?.unwrap_or_default();
            // A DOTTED path is refused, and this is not fussiness: nyet runs
            // `distinct` as a bounded aggregation (see `command`), and
            // `$unwind` does not descend THROUGH an array on the way to a
            // sub-field. For `{items: [{sku: 1}, {sku: 2}]}` the command
            // answers `[1, 2]` while the pipeline answers the whole arrays plus
            // a null — a wrong answer that reads like a complete one, which is
            // exactly the failure the row-limit work removed. Refusing is the
            // honest half of the trade that bought the row limit.
            if key.contains('.') {
                return refuse(
                    DENIED_COMMAND,
                    format!(
                        "nyet: distinct(\"{key}\") walks into a sub-document, and nyet cannot \
                         answer that correctly"
                    ),
                    format!(
                        "nyet runs distinct as an aggregation so the row limit applies, and \
                         that cannot descend through an array on its own. Write it \
                         explicitly, which also lets you see what is unwound: \
                         db.<collection>.aggregate([{{ $unwind: \"$<array field>\" }}, \
                         {{ $group: {{ _id: \"${key}\" }} }}]) — a dotted path with no array \
                         in it works the same way"
                    ),
                );
            }
            Ok(Op::Distinct { key, filter })
        }
        // Unreachable: ALLOWED_METHODS is checked above and every entry is
        // handled here. Refuse rather than panic (Д3).
        _ => refuse(
            DENIED_COMMAND,
            format!("nyet: `{method}` is not on nyet's read allowlist for MongoDB"),
            format!("allowed methods: {}", ALLOWED_METHODS.join(", ")),
        ),
    }
}

/// `.sort(..)`, `.skip(n)`, `.limit(n)`, `.toArray()` after a `find`. A repeated
/// call is refused rather than silently taking the last one — mongosh's
/// last-wins rule is exactly the kind of quiet reinterpretation nyet avoids.
fn apply_chain(op: &mut Op, name: &str, mut args: Vec<Bson>) -> Result<(), Refusal> {
    if !is_listed(ALLOWED_CHAIN, name) {
        return refuse(
            DENIED_COMMAND,
            format!("nyet: the cursor method `.{name}()` is not on nyet's read allowlist"),
            format!(
                "allowed after find(): {}; ordering and paging belong in .sort()/.skip()/\
                 .limit(), and the result is always materialized by nyet",
                ALLOWED_CHAIN.join(", ")
            ),
        );
    }
    let Op::Find {
        sort, skip, limit, ..
    } = op
    else {
        return refuse(
            DENIED_COMMAND,
            format!(
                "nyet: `.{name}()` can only follow find(); aggregate/countDocuments/distinct \
                 return no cursor nyet can chain onto"
            ),
            "put $sort / $skip / $limit stages in the pipeline instead, or use find()",
        );
    };
    let taken = |slot: &Option<i64>| slot.is_some();
    let int_arg = |args: Vec<Bson>| -> Result<i64, Refusal> {
        match args.as_slice() {
            [Bson::Int32(n)] => Ok(i64::from(*n)),
            [Bson::Int64(n)] => Ok(*n),
            _ => refuse(
                PARSE_FAILED,
                format!("nyet: `.{name}()` takes one integer argument"),
                format!("write it as .{name}(100)"),
            ),
        }
    };
    match name {
        "toArray" => {
            if !args.is_empty() {
                return refuse(
                    PARSE_FAILED,
                    "nyet: `.toArray()` takes no arguments",
                    syntax_hint(),
                );
            }
            Ok(())
        }
        "sort" => {
            if sort.is_some() {
                return refuse(
                    PARSE_FAILED,
                    "nyet: `.sort()` is given twice",
                    "call each cursor method at most once — a repeated call would silently \
                     discard the earlier one",
                );
            }
            match args.pop() {
                Some(Bson::Document(d)) if args.is_empty() && !d.is_empty() => {
                    *sort = Some(d);
                    Ok(())
                }
                _ => refuse(
                    PARSE_FAILED,
                    "nyet: `.sort()` takes one non-empty document",
                    "write it as .sort({ created_at: -1 })",
                ),
            }
        }
        "skip" => {
            if taken(skip) {
                return refuse(
                    PARSE_FAILED,
                    "nyet: `.skip()` is given twice",
                    "call each cursor method at most once",
                );
            }
            let n = int_arg(args)?;
            if n < 0 {
                return refuse(
                    PARSE_FAILED,
                    "nyet: `.skip()` must not be negative",
                    "use .skip(0) or a positive number",
                );
            }
            *skip = Some(n);
            Ok(())
        }
        "limit" => {
            if taken(limit) {
                return refuse(
                    PARSE_FAILED,
                    "nyet: `.limit()` is given twice",
                    "call each cursor method at most once",
                );
            }
            let n = int_arg(args)?;
            if n < 1 {
                return refuse(
                    PARSE_FAILED,
                    "nyet: `.limit()` must be at least 1",
                    "MongoDB reads .limit(0) as \"no limit\", which is ambiguous here — say \
                     how many rows you want, or omit .limit() and let the connection's \
                     row_limit apply",
                );
            }
            *limit = Some(n);
            Ok(())
        }
        // Unreachable: ALLOWED_CHAIN is checked above.
        _ => refuse(
            DENIED_COMMAND,
            format!("nyet: the cursor method `.{name}()` is not on nyet's read allowlist"),
            format!("allowed after find(): {}", ALLOWED_CHAIN.join(", ")),
        ),
    }
}

/// One value: JSON plus the mongosh type constructors and regex literals.
fn parse_value(p: &mut Parser, depth: usize) -> Result<Bson, Refusal> {
    if depth > MAX_DEPTH {
        return refuse(
            PARSE_FAILED,
            format!("nyet: the query nests deeper than nyet's limit of {MAX_DEPTH} levels"),
            "flatten the filter; MongoDB itself refuses documents nested past 100 levels",
        );
    }
    p.skip_ws()?;
    match p.peek() {
        None => refuse(
            PARSE_FAILED,
            "nyet: the query ends where a value was expected",
            syntax_hint(),
        ),
        Some('{') => parse_document(p, depth),
        Some('[') => {
            p.pos += 1;
            let mut items = Vec::new();
            loop {
                p.skip_ws()?;
                if p.at(']') {
                    p.pos += 1;
                    return Ok(Bson::Array(items));
                }
                if !items.is_empty() {
                    return refuse(
                        PARSE_FAILED,
                        format!(
                            "nyet: expected ',' or ']' in an array, found {}",
                            p.describe_here()
                        ),
                        syntax_hint(),
                    );
                }
                loop {
                    items.push(parse_value(p, depth + 1)?);
                    p.skip_ws()?;
                    if p.at(',') {
                        p.pos += 1;
                        p.skip_ws()?;
                        if p.at(']') {
                            break;
                        }
                        continue;
                    }
                    break;
                }
            }
        }
        Some('"') | Some('\'') => Ok(Bson::String(parse_string(p)?)),
        Some('/') => parse_regex(p),
        Some(c) if c.is_ascii_digit() || c == '-' => parse_number(p),
        Some(c) if c.is_ascii_alphabetic() || c == '_' || c == '$' => parse_word(p, depth),
        Some(_) => refuse(
            PARSE_FAILED,
            format!(
                "nyet: unexpected {} where a value was expected",
                p.describe_here()
            ),
            syntax_hint(),
        ),
    }
}

/// `{ key: value, ... }` — duplicate keys are REFUSED. BSON permits them, and
/// every JSON parser silently keeps one; either choice would mean nyet
/// classifies a document that is not the one the server evaluates, so nyet
/// refuses to guess (fail closed).
fn parse_document(p: &mut Parser, depth: usize) -> Result<Bson, Refusal> {
    p.expect('{', "to open a document")?;
    let mut doc = Document::new();
    loop {
        p.skip_ws()?;
        if p.at('}') {
            p.pos += 1;
            return finish_document(doc);
        }
        if !doc.is_empty() {
            return refuse(
                PARSE_FAILED,
                format!(
                    "nyet: expected ',' or '}}' in a document, found {}",
                    p.describe_here()
                ),
                syntax_hint(),
            );
        }
        loop {
            p.skip_ws()?;
            let key = match p.peek() {
                Some('"') | Some('\'') => parse_string(p)?,
                Some(c) if c.is_ascii_alphabetic() || c == '_' || c == '$' => p.ident(),
                _ => {
                    return refuse(
                        PARSE_FAILED,
                        format!(
                            "nyet: expected a field name in a document, found {}",
                            p.describe_here()
                        ),
                        syntax_hint(),
                    )
                }
            };
            if doc.contains_key(&key) {
                return refuse(
                    PARSE_FAILED,
                    format!("nyet: the field '{key}' appears twice in the same document"),
                    "BSON allows duplicate field names but their meaning is ambiguous, so \
                     nyet refuses instead of silently keeping one — write each field once",
                );
            }
            p.expect(':', "after a field name")?;
            let value = parse_value(p, depth + 1)?;
            doc.insert(key, value);
            p.skip_ws()?;
            if p.at(',') {
                p.pos += 1;
                p.skip_ws()?;
                if p.at('}') {
                    break;
                }
                continue;
            }
            break;
        }
    }
}

/// Extended-JSON type wrappers in VALUE position (`{"$oid": ".."}`,
/// `{"$date": ..}`, ...) are resolved into the native BSON type right here, so
/// the classifier below never has to guess whether a `$`-key names a TYPE or an
/// OPERATOR — by the time it runs, only operator keys are left.
///
/// A wrapper whose payload has the wrong shape is a refusal, never a fallback
/// to "treat it as an operator document": that fallback is exactly how a
/// `{"$oid": {"$where": ...}}` would slip past a shape check.
fn finish_document(doc: Document) -> Result<Bson, Refusal> {
    if doc.len() != 1 {
        return Ok(Bson::Document(doc));
    }
    let Some(key) = doc.keys().next().cloned() else {
        return Ok(Bson::Document(doc));
    };
    if !EXT_JSON_KEYS.contains(&key.as_str()) {
        return Ok(Bson::Document(doc));
    }
    // Cloned so the `doc` above can still be returned/consumed below.
    let value = &doc.get(&key).cloned().unwrap_or(Bson::Null);
    let bad = |what: &str| -> Result<Bson, Refusal> {
        refuse(
            PARSE_FAILED,
            format!("nyet: '{key}' is an extended-JSON type but its value is not {what}"),
            "write extended JSON canonically, e.g. {\"$oid\": \"66210f0e2f1a4b0012a3c4d5\"} \
             or {\"$date\": \"2026-01-31T00:00:00Z\"} — or use the mongosh constructors \
             ObjectId(\"..\") / ISODate(\"..\")",
        )
    };
    let text = |v: &Bson| match v {
        Bson::String(s) => Some(s.clone()),
        _ => None,
    };
    match key.as_str() {
        "$oid" => match text(value).map(mongodb::bson::oid::ObjectId::parse_str) {
            Some(Ok(oid)) => Ok(Bson::ObjectId(oid)),
            _ => bad("a 24-character hex string"),
        },
        "$date" => match value {
            Bson::String(s) => match mongodb::bson::DateTime::parse_rfc3339_str(s) {
                Ok(dt) => Ok(Bson::DateTime(dt)),
                Err(_) => bad("an RFC 3339 timestamp"),
            },
            Bson::Int64(ms) => Ok(Bson::DateTime(mongodb::bson::DateTime::from_millis(*ms))),
            Bson::Int32(ms) => Ok(Bson::DateTime(mongodb::bson::DateTime::from_millis(
                i64::from(*ms),
            ))),
            _ => bad("an RFC 3339 timestamp or a millisecond count"),
        },
        "$numberLong" => match text(value).map(|s| i64::from_str(&s)) {
            Some(Ok(n)) => Ok(Bson::Int64(n)),
            _ => bad("a decimal string that fits a 64-bit integer"),
        },
        "$numberInt" => match text(value).map(|s| i32::from_str(&s)) {
            Some(Ok(n)) => Ok(Bson::Int32(n)),
            _ => bad("a decimal string that fits a 32-bit integer"),
        },
        "$numberDouble" => match text(value).map(|s| f64::from_str(&s)) {
            Some(Ok(n)) => Ok(Bson::Double(n)),
            _ => bad("a decimal string that parses as a double"),
        },
        "$numberDecimal" => match text(value).map(|s| Decimal128::from_str(&s)) {
            Some(Ok(d)) => Ok(Bson::Decimal128(d)),
            _ => bad("a decimal string"),
        },
        // The payload is part of the canonical form, and it is not ignored:
        // `{"$minKey": {"$where": ".."}}` must not become a MinKey that erased
        // an operator before the classifier could see it.
        "$minKey" => match value {
            Bson::Int32(1) | Bson::Int64(1) => Ok(Bson::MinKey),
            _ => bad("exactly 1"),
        },
        "$maxKey" => match value {
            Bson::Int32(1) | Bson::Int64(1) => Ok(Bson::MaxKey),
            _ => bad("exactly 1"),
        },
        "$regularExpression" => match value {
            Bson::Document(inner) => {
                let (Ok(pattern), Ok(options)) =
                    (inner.get_str("pattern"), inner.get_str("options"))
                else {
                    return bad("{\"pattern\": \"..\", \"options\": \"..\"}");
                };
                // Exactly the two canonical fields: an extra one would be
                // dropped here, taking whatever it carried with it.
                if inner.len() != 2 {
                    return bad("exactly {\"pattern\": \"..\", \"options\": \"..\"}");
                }
                Ok(Bson::RegularExpression(Regex {
                    pattern: pattern.to_string(),
                    options: check_regex_options(options)?,
                }))
            }
            _ => bad("{\"pattern\": \"..\", \"options\": \"..\"}"),
        },
        "$timestamp" => match value {
            Bson::Document(inner) if inner.len() == 2 => {
                let (Some(time), Some(increment)) = (
                    inner
                        .get_i64("t")
                        .ok()
                        .or(inner.get_i32("t").ok().map(i64::from)),
                    inner
                        .get_i64("i")
                        .ok()
                        .or(inner.get_i32("i").ok().map(i64::from)),
                ) else {
                    return bad("{\"t\": <seconds>, \"i\": <increment>}");
                };
                let (Ok(time), Ok(increment)) = (u32::try_from(time), u32::try_from(increment))
                else {
                    return bad("two 32-bit unsigned integers");
                };
                Ok(Bson::Timestamp(mongodb::bson::Timestamp {
                    time,
                    increment,
                }))
            }
            _ => bad("exactly {\"t\": <seconds>, \"i\": <increment>}"),
        },
        // Binary is READ back as `{"$binary": {...}}` but cannot be written
        // here: decoding base64 would mean a decoder of nyet's own for a value
        // no read needs to match on. The refusal says so instead of calling a
        // BSON TYPE an unknown operator, which is what happened before.
        "$binary" => refuse(
            DENIED_OPERATOR,
            "nyet: '$binary' is a BSON type nyet can return but not accept in a query",
            "match on another field, or — for a UUID, the common case — write it as \
             UUID(\"3b241101-e2bb-4255-8caf-4136c566a962\")",
        ),
        // Server-side JavaScript as a BSON VALUE. Never accepted, in any
        // position — a $code value is what $where and stored JS are made of.
        "$code" | "$codeWithScope" => refuse(
            DENIED_FUNCTION,
            format!("nyet: '{key}' embeds JavaScript for the database server to run"),
            "nyet never sends JavaScript to the server; express the logic as an \
             aggregation pipeline instead",
        ),
        // Unreachable: EXT_JSON_KEYS lists exactly the arms above.
        _ => Ok(Bson::Document(doc)),
    }
}

/// The extended-JSON type wrappers `finish_document` resolves (plus the two JS
/// ones it refuses). None of these names collides with a query operator or an
/// aggregation stage, which is what makes the position question decidable at
/// all — and a wrapper with the wrong payload is refused rather than demoted
/// back to "probably an operator".
const EXT_JSON_KEYS: &[&str] = &[
    "$binary",
    "$code",
    "$codeWithScope",
    "$date",
    "$maxKey",
    "$minKey",
    "$numberDecimal",
    "$numberDouble",
    "$numberInt",
    "$numberLong",
    "$oid",
    "$regularExpression",
    "$timestamp",
];

/// A quoted string with JSON escapes (both quote styles, as mongosh allows).
fn parse_string(p: &mut Parser) -> Result<String, Refusal> {
    let Some(quote) = p.bump() else {
        return refuse(PARSE_FAILED, "nyet: expected a string", syntax_hint());
    };
    let mut out = String::new();
    loop {
        let Some(c) = p.bump() else {
            return refuse(
                PARSE_FAILED,
                "nyet: unterminated string in the query",
                syntax_hint(),
            );
        };
        if c == quote {
            return Ok(out);
        }
        if c != '\\' {
            out.push(c);
            continue;
        }
        let Some(esc) = p.bump() else {
            return refuse(
                PARSE_FAILED,
                "nyet: the query ends inside a string escape",
                syntax_hint(),
            );
        };
        match esc {
            '"' | '\'' | '\\' | '/' => out.push(esc),
            'b' => out.push('\u{8}'),
            'f' => out.push('\u{c}'),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            'u' => out.push(parse_unicode_escape(p)?),
            other => {
                return refuse(
                    PARSE_FAILED,
                    format!("nyet: unsupported string escape '\\{other}'"),
                    "supported escapes: \\\" \\' \\\\ \\/ \\b \\f \\n \\r \\t \\uXXXX",
                )
            }
        }
    }
}

/// `\uXXXX`, including a surrogate PAIR. A lone surrogate is refused: it cannot
/// become a `char`, and silently replacing it would change the value being
/// matched.
fn parse_unicode_escape(p: &mut Parser) -> Result<char, Refusal> {
    let bad = || -> Refusal {
        Refusal {
            reason: PARSE_FAILED,
            message: "nyet: malformed \\uXXXX escape in a string".to_string(),
            hint: "write four hex digits (\\u00e9); a character outside the basic plane \
                   needs a surrogate pair (\\ud83d\\ude00) or can be written literally"
                .to_string(),
        }
    };
    let hex4 = |p: &mut Parser| -> Result<u32, Refusal> {
        let mut v: u32 = 0;
        for _ in 0..4 {
            let d = p.bump().and_then(|c| c.to_digit(16)).ok_or_else(bad)?;
            v = v * 16 + d;
        }
        Ok(v)
    };
    let first = hex4(p)?;
    if !(0xD800..0xDC00).contains(&first) {
        return char::from_u32(first).ok_or_else(bad);
    }
    if p.bump() != Some('\\') || p.bump() != Some('u') {
        return Err(bad());
    }
    let second = hex4(p)?;
    if !(0xDC00..0xE000).contains(&second) {
        return Err(bad());
    }
    let combined = 0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00);
    char::from_u32(combined).ok_or_else(bad)
}

/// A JSON number. An integer literal becomes Int32 when it fits and Int64
/// otherwise (what mongosh does); anything with a fraction or an exponent is a
/// double.
fn parse_number(p: &mut Parser) -> Result<Bson, Refusal> {
    let start = p.pos;
    if p.at('-') {
        p.pos += 1;
    }
    let mut float = false;
    while let Some(c) = p.peek() {
        match c {
            '0'..='9' => p.pos += 1,
            '.' | 'e' | 'E' => {
                float = true;
                p.pos += 1;
            }
            '+' | '-'
                if matches!(
                    p.pos.checked_sub(1).and_then(|i| p.chars.get(i)),
                    Some('e') | Some('E')
                ) =>
            {
                p.pos += 1
            }
            _ => break,
        }
    }
    let text: String = p.chars[start..p.pos].iter().collect();
    let bad = || -> Result<Bson, Refusal> {
        refuse(
            PARSE_FAILED,
            format!("nyet: '{text}' is not a number nyet can read"),
            "write a JSON number (12, -3.5, 1e6); for a value that needs 64-bit or \
             decimal precision use NumberLong(..) / NumberDecimal(\"..\")",
        )
    };
    if float {
        return match f64::from_str(&text) {
            Ok(v) if v.is_finite() => Ok(Bson::Double(v)),
            _ => bad(),
        };
    }
    match i64::from_str(&text) {
        Ok(v) => Ok(match i32::try_from(v) {
            Ok(small) => Bson::Int32(small),
            Err(_) => Bson::Int64(v),
        }),
        Err(_) => bad(),
    }
}

/// `/pattern/flags`. The scan tracks escapes and character classes, because a
/// `/` inside `[...]` does not end the literal in JS.
fn parse_regex(p: &mut Parser) -> Result<Bson, Refusal> {
    p.pos += 1; // the opening '/'
    let mut pattern = String::new();
    let mut in_class = false;
    loop {
        let Some(c) = p.bump() else {
            return refuse(
                PARSE_FAILED,
                "nyet: unterminated regular expression in the query",
                "close it with '/', e.g. /^acme/i",
            );
        };
        match c {
            '\\' => {
                let Some(next) = p.bump() else {
                    return refuse(
                        PARSE_FAILED,
                        "nyet: the query ends inside a regular-expression escape",
                        "close it with '/', e.g. /^acme/i",
                    );
                };
                pattern.push('\\');
                pattern.push(next);
            }
            '[' => {
                in_class = true;
                pattern.push(c);
            }
            ']' => {
                in_class = false;
                pattern.push(c);
            }
            '/' if !in_class => break,
            _ => pattern.push(c),
        }
    }
    let start = p.pos;
    while p.peek().is_some_and(|c| c.is_ascii_alphabetic()) {
        p.pos += 1;
    }
    let flags: String = p.chars[start..p.pos].iter().collect();
    Ok(Bson::RegularExpression(Regex {
        pattern,
        options: check_regex_options(&flags)?,
    }))
}

/// MongoDB accepts exactly `imsx` as regex options (`u` and `g` are JS-only and
/// the server rejects them). Refuse the rest rather than dropping them — a
/// silently dropped flag changes which documents match.
fn check_regex_options(flags: &str) -> Result<String, Refusal> {
    let mut seen: Vec<char> = Vec::new();
    for c in flags.chars() {
        if !matches!(c, 'i' | 'm' | 's' | 'x') {
            return Err(Refusal {
                reason: PARSE_FAILED,
                message: format!("nyet: '{c}' is not a regular-expression option MongoDB accepts"),
                hint: "MongoDB supports i (case-insensitive), m (multiline), s (dotall) and \
                       x (extended); the JavaScript-only g/u/y flags have no meaning in a query"
                    .to_string(),
            });
        }
        if !seen.contains(&c) {
            seen.push(c);
        }
    }
    seen.sort_unstable();
    Ok(seen.into_iter().collect())
}

/// A bare word: `true`/`false`/`null`, or a mongosh type constructor
/// (optionally written with `new`).
fn parse_word(p: &mut Parser, depth: usize) -> Result<Bson, Refusal> {
    let word = p.ident();
    match word.as_str() {
        "true" => return Ok(Bson::Boolean(true)),
        "false" => return Ok(Bson::Boolean(false)),
        "null" => return Ok(Bson::Null),
        "new" => {
            p.skip_ws()?;
            let ctor = p.ident();
            return parse_ctor(p, &ctor, depth);
        }
        _ => {}
    }
    parse_ctor(p, &word, depth)
}

/// The mongosh type constructors nyet understands. Everything else (including
/// `Date()` with no argument, `eval`, or a bare identifier the agent meant as a
/// variable) is refused: nyet evaluates no JavaScript, so there is nothing else
/// a word could mean.
fn parse_ctor(p: &mut Parser, name: &str, depth: usize) -> Result<Bson, Refusal> {
    let known = matches!(
        name,
        "ObjectId" | "ISODate" | "Date" | "NumberLong" | "NumberInt" | "NumberDecimal" | "UUID"
    );
    if !known {
        return refuse(
            PARSE_FAILED,
            match name.is_empty() {
                true => format!(
                    "nyet: unexpected {} where a value was expected",
                    p.describe_here()
                ),
                false => format!("nyet: '{name}' is not a value nyet understands"),
            },
            "nyet evaluates no JavaScript: values are JSON literals plus ObjectId(\"..\"), \
             ISODate(\"..\"), NumberLong(..), NumberInt(..), NumberDecimal(\"..\"), \
             UUID(\"..\") and /regex/i",
        );
    }
    let args = parse_args(p, depth)?;
    let one_string = |args: &[Bson]| -> Option<String> {
        match args {
            [Bson::String(s)] => Some(s.clone()),
            _ => None,
        }
    };
    let bad = |what: &str| -> Result<Bson, Refusal> {
        refuse(
            PARSE_FAILED,
            format!("nyet: {name}(..) needs {what}"),
            syntax_hint(),
        )
    };
    match name {
        "ObjectId" => match one_string(&args).map(mongodb::bson::oid::ObjectId::parse_str) {
            Some(Ok(oid)) => Ok(Bson::ObjectId(oid)),
            _ => bad("one 24-character hex string, e.g. ObjectId(\"66210f0e2f1a4b0012a3c4d5\")"),
        },
        // `ISODate()` / `new Date()` with no argument means "now" in mongosh —
        // refused on purpose: a query whose meaning depends on the clock is not
        // reproducible from the audit log.
        "ISODate" | "Date" => {
            match one_string(&args).map(mongodb::bson::DateTime::parse_rfc3339_str) {
                Some(Ok(dt)) => Ok(Bson::DateTime(dt)),
                _ => bad(
                    "one RFC 3339 timestamp, e.g. ISODate(\"2026-01-31T00:00:00Z\") — the \
                 no-argument form (\"now\") is not accepted, write the instant out",
                ),
            }
        }
        "NumberLong" => match args.as_slice() {
            [Bson::Int32(n)] => Ok(Bson::Int64(i64::from(*n))),
            [Bson::Int64(n)] => Ok(Bson::Int64(*n)),
            [Bson::String(s)] => match i64::from_str(s) {
                Ok(n) => Ok(Bson::Int64(n)),
                Err(_) => bad("a 64-bit integer, e.g. NumberLong(\"9007199254740993\")"),
            },
            _ => bad("a 64-bit integer, e.g. NumberLong(\"9007199254740993\")"),
        },
        "NumberInt" => match args.as_slice() {
            [Bson::Int32(n)] => Ok(Bson::Int32(*n)),
            [Bson::String(s)] => match i32::from_str(s) {
                Ok(n) => Ok(Bson::Int32(n)),
                Err(_) => bad("a 32-bit integer, e.g. NumberInt(7)"),
            },
            _ => bad("a 32-bit integer, e.g. NumberInt(7)"),
        },
        "NumberDecimal" => {
            let text = match args.as_slice() {
                [Bson::String(s)] => Some(s.clone()),
                [Bson::Int32(n)] => Some(n.to_string()),
                [Bson::Int64(n)] => Some(n.to_string()),
                [Bson::Double(n)] => Some(n.to_string()),
                _ => None,
            };
            match text.map(|s| Decimal128::from_str(&s)) {
                Some(Ok(d)) => Ok(Bson::Decimal128(d)),
                _ => bad("a decimal string, e.g. NumberDecimal(\"19.99\")"),
            }
        }
        "UUID" => match one_string(&args).map(mongodb::bson::Uuid::parse_str) {
            Some(Ok(u)) => Ok(Bson::Binary(u.into())),
            _ => bad("one UUID string, e.g. UUID(\"3b241101-e2bb-4255-8caf-4136c566a962\")"),
        },
        // Unreachable: `known` above lists exactly these names.
        _ => bad("a supported type constructor"),
    }
}

// ---------------------------------------------------------------------------
// Classifier — the security boundary
// ---------------------------------------------------------------------------

/// Walk everything the parser produced and refuse any `$`-key that is not on an
/// allowlist. This is the layer that has to be complete, so it is deliberately
/// dumb: ONE recursive walk, no shape-specific shortcuts, no "this branch
/// cannot contain an operator" assumptions.
pub fn classify(request: &Request) -> Result<(), Refusal> {
    match &request.op {
        Op::Find {
            filter,
            projection,
            sort,
            ..
        } => {
            walk_doc(filter, 0)?;
            if let Some(p) = projection {
                walk_doc(p, 0)?;
            }
            if let Some(s) = sort {
                walk_doc(s, 0)?;
            }
            Ok(())
        }
        Op::Aggregate { pipeline } => walk_pipeline(pipeline, 0),
        Op::Count { filter } => walk_doc(filter, 0),
        Op::Distinct { filter, .. } => walk_doc(filter, 0),
    }
}

/// A pipeline: an array of single-key stage documents, each named by an
/// allowlisted stage. `$out` and `$merge` are refused HERE as well as by the
/// allowlist, in EVERY pipeline — top level or nested. The server happens to
/// accept them only as the final top-level stage today; nyet does not rely on
/// that, because the rule that protects the data must not be the server's
/// grammar.
fn walk_pipeline(pipeline: &[Bson], depth: usize) -> Result<(), Refusal> {
    if depth > MAX_DEPTH {
        return too_deep();
    }
    for (i, stage) in pipeline.iter().enumerate() {
        let Bson::Document(doc) = stage else {
            return refuse(
                PARSE_FAILED,
                format!("nyet: pipeline stage {} is not a document", i + 1),
                "every stage is a document with exactly one $-operator, e.g. \
                 { $match: { active: true } }",
            );
        };
        if doc.len() != 1 {
            return refuse(
                PARSE_FAILED,
                format!(
                    "nyet: pipeline stage {} has {} fields; a stage has exactly one",
                    i + 1,
                    doc.len()
                ),
                "split it: [{ $match: {...} }, { $project: {...} }]",
            );
        }
        for (key, value) in doc {
            check_key(key, true)?;
            walk_value_of(key, value, depth + 1)?;
        }
    }
    Ok(())
}

fn walk_doc(doc: &Document, depth: usize) -> Result<(), Refusal> {
    if depth > MAX_DEPTH {
        return too_deep();
    }
    for (key, value) in doc {
        check_key(key, false)?;
        walk_value_of(key, value, depth + 1)?;
    }
    Ok(())
}

/// The ONE rule about which collections nyet reads, called from BOTH places a
/// collection can be named: `db.<collection>.<method>` at parse time, and a
/// stage that names another collection at classify time (`$lookup.from`,
/// `$unionWith`, `$graphLookup.from`). It used to live only in the parser —
/// and `{$lookup: {from: "system.js"}}` walked straight past it, because a
/// collection name is a string VALUE and the classifier only ever looked at
/// `$`-KEYS. Verified live: under the README's own `read`-role recipe that
/// returned the stored JavaScript, and on a server without auth it returned
/// `system.profile`, i.e. other sessions' queries WITH their values.
fn check_collection_name(name: &str) -> Result<(), Refusal> {
    if !name.starts_with("system.") {
        return Ok(());
    }
    refuse(
        DENIED_COMMAND,
        format!("nyet: '{name}' is a MongoDB internal catalog, not a data collection"),
        "query your own collections; the internal `system.*` catalogs hold stored \
         JavaScript, view definitions and profiler output (which quotes real query \
         values), so nyet does not read them — from a stage's `from`/`coll` just as \
         much as from db.<collection>",
    )
}

/// The collection a stage reads BESIDES the one the query names. Only the three
/// stages that can do so are inspected, and only their own `from`/`coll`
/// fields — so an ordinary document field that happens to be called `from`
/// (`db.mail.find({from: "system.import"})`) is untouched. A future stage that
/// names a collection is not a hole: it would have to be added to `STAGES`
/// first, and this list is next to it.
fn check_collection_source(stage: &str, value: &Bson) -> Result<(), Refusal> {
    if !is_listed(NAMESPACE_STAGES, stage) {
        return Ok(());
    }
    // `{$unionWith: "other"}` — the string IS the collection.
    if let Bson::String(name) = value {
        return check_collection_name(name);
    }
    let Bson::Document(doc) = value else {
        return Ok(());
    };
    for field in ["from", "coll"] {
        match doc.get(field) {
            Some(Bson::String(name)) => check_collection_name(name)?,
            // `from: {db: "admin", coll: "system.users"}` — a namespace in
            // another DATABASE. Today's server refuses it outside Atlas; nyet
            // refuses it itself, because "the server would have said no" is not
            // a rule, and the connection's url names the ONE database nyet reads.
            Some(Bson::Document(_)) => {
                return refuse(
                    DENIED_COMMAND,
                    format!("nyet: the '{stage}' stage names a collection in another database"),
                    "nyet reads exactly the database named in this connection's url and \
                     offers no way to reach another one; write `from: \"<collection>\"` \
                     without a `db` qualifier, or ask the config owner for a second \
                     connection",
                );
            }
            _ => {}
        }
    }
    Ok(())
}

/// The value of one field, with the two structural exceptions that carry
/// NESTED PIPELINES — `$lookup`/`$unionWith` (`pipeline: [...]`) and `$facet`
/// (every value is a pipeline). Missing them would not be a hole (the union
/// allowlist covers stage names too) but it would make legitimate stages read
/// as stray operators; getting them right is what makes the message honest.
fn walk_value_of(key: &str, value: &Bson, depth: usize) -> Result<(), Refusal> {
    check_collection_source(key, value)?;
    if key == "$facet" {
        if let Bson::Document(facets) = value {
            for (name, sub) in facets {
                // A branch NAME is a document key like any other: without this
                // a `$`-prefixed one travelled to the server unclassified.
                check_key(name, false)?;
                let Bson::Array(pipeline) = sub else {
                    return refuse(
                        PARSE_FAILED,
                        format!("nyet: the $facet branch '{name}' is not a pipeline array"),
                        "each $facet branch is an array of stages: \
                         { $facet: { byStatus: [{ $group: {...} }] } }",
                    );
                };
                walk_pipeline(pipeline, depth + 1)?;
            }
            return Ok(());
        }
    }
    if key == "pipeline" {
        if let Bson::Array(pipeline) = value {
            return walk_pipeline(pipeline, depth + 1);
        }
    }
    walk_value(value, depth)
}

fn walk_value(value: &Bson, depth: usize) -> Result<(), Refusal> {
    if depth > MAX_DEPTH {
        return too_deep();
    }
    match value {
        Bson::Document(doc) => walk_doc(doc, depth),
        Bson::Array(items) => {
            for item in items {
                walk_value(item, depth + 1)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn too_deep<T>() -> Result<T, Refusal> {
    refuse(
        PARSE_FAILED,
        format!("nyet: the query nests deeper than nyet's limit of {MAX_DEPTH} levels"),
        "flatten the filter or the pipeline",
    )
}

/// The single gate every `$`-key passes through. A key that does not start with
/// `$` is a field name and needs no permission.
fn check_key(key: &str, stage_position: bool) -> Result<(), Refusal> {
    if !key.starts_with('$') {
        return Ok(());
    }
    if is_listed(WRITE_KEYS, key) {
        return refuse(
            WRITE_OPERATION,
            format!("nyet: the '{key}' stage writes its result into a collection"),
            "nyet is read-only: drop the stage and read the pipeline's output instead — \
             every document it would have written is what the query returns",
        );
    }
    if is_listed(JS_KEYS, key) {
        return refuse(
            DENIED_FUNCTION,
            format!("nyet: '{key}' runs JavaScript inside the database server"),
            "server-side JavaScript is never allowed (it runs arbitrary code in the \
             database process and is not bounded by the query timeout); express the same \
             condition with query operators or an $expr aggregation expression",
        );
    }
    if is_listed(NYET_OWNED, key) {
        return refuse(
            DENIED_OPERATOR,
            format!("nyet: '{key}' is a command option nyet sets itself"),
            "nyet owns the row limit, the batch size and maxTimeMS (see --limit and \
             --timeout); an agent-supplied option would override the very bounds that \
             make the query safe",
        );
    }
    if stage_position {
        if is_listed(STAGES, key) {
            return Ok(());
        }
        return refuse(
            DENIED_OPERATOR,
            format!("nyet: the pipeline stage '{key}' is not on nyet's read allowlist"),
            format!(
                "allowed stages: {}. Everything else is refused by default — writes \
                 ($out, $merge), server JavaScript ($function, $accumulator), unbounded \
                 cursors ($changeStream), Atlas-only stages ($search, $vectorSearch), \
                 cluster introspection ($currentOp, $collStats, $planCacheStats) and every \
                 undocumented $_internal stage",
                STAGES.join(", ")
            ),
        );
    }
    // Outside stage position both lists apply: stage names appear inside nested
    // pipelines that this walk did not recognize structurally, and letting them
    // through there costs nothing (the server judges them) while refusing them
    // would be a false refusal.
    if is_listed(OPS, key) || is_listed(STAGES, key) {
        return Ok(());
    }
    refuse(
        DENIED_OPERATOR,
        format!("nyet: the operator '{key}' is not on nyet's read allowlist"),
        "nyet allows an explicit list of query operators, aggregation expressions and \
         accumulators; anything else — including operators a newer MongoDB adds — is \
         refused until it has been reviewed. Check the spelling, or express the condition \
         with the documented operators ($eq, $gt, $in, $regex, $elemMatch, $expr, ...)",
    )
}

// ---------------------------------------------------------------------------
// The wire command, and reading the reply — pure, so the engine only does IO
// ---------------------------------------------------------------------------

impl Request {
    /// The command document nyet sends. Every bound in it is nyet's own:
    /// `limit`/`batchSize` implement the row limit (fetch limit+1 to detect
    /// truncation), `singleBatch` keeps a `find` to ONE round trip with a
    /// server-closed cursor, and `maxTimeMS` is the server-side half of the
    /// timeout. None of them can be set by the agent (see `NYET_OWNED`).
    ///
    /// `fetch_limit` is `None` for one caller only — [`explain_command`], which
    /// describes the query's SHAPE and fetches nothing, so nyet's own row limit
    /// would appear in the plan as a `LIMIT` stage the agent never wrote.
    ///
    /// [`explain_command`]: Self::explain_command
    pub fn command(&self, fetch_limit: Option<u64>, max_time_ms: u64) -> Document {
        let fetch = fetch_limit.map(|n| i64::try_from(n).unwrap_or(i64::MAX).max(1));
        let max_time = i32::try_from(max_time_ms).unwrap_or(i32::MAX);
        let mut cmd = Document::new();
        match &self.op {
            Op::Find {
                filter,
                projection,
                sort,
                skip,
                limit,
            } => {
                cmd.insert("find", self.collection.clone());
                cmd.insert("filter", filter.clone());
                if let Some(p) = projection {
                    cmd.insert("projection", p.clone());
                }
                if let Some(s) = sort {
                    cmd.insert("sort", s.clone());
                }
                if let Some(n) = skip {
                    cmd.insert("skip", *n);
                }
                // The agent's own limit never RAISES nyet's: the connection's
                // row_limit is the config owner's word.
                let effective = match (fetch, limit) {
                    (Some(fetch), Some(n)) => Some(fetch.min(*n)),
                    (Some(fetch), None) => Some(fetch),
                    (None, agent) => *agent,
                };
                if let Some(n) = effective {
                    cmd.insert("limit", n);
                }
                // `batchSize`, NOT `singleBatch`. Both keep the read to one
                // round trip, but `singleBatch` makes the server close the
                // cursor whatever happened — and the server cuts a batch at
                // 16 MiB BEFORE it reaches `limit`, so with `singleBatch` the
                // rest was lost with no signal at all and the answer read as
                // complete (measured: 30 documents of ~1 MB came back as 16,
                // `truncated: false`). With `batchSize` the server leaves the
                // cursor OPEN when it cut the batch, which `read_reply` reads
                // as truncation. Without a batch size the first batch would be
                // the protocol default of 101 documents, which would truncate
                // at 101 instead of at the row limit.
                if let Some(n) = effective {
                    cmd.insert("batchSize", n);
                }
            }
            Op::Aggregate { pipeline } => {
                let mut stages = pipeline.clone();
                if let Some(fetch) = fetch {
                    let mut limit = Document::new();
                    limit.insert("$limit", fetch);
                    stages.push(Bson::Document(limit));
                }
                cmd.insert("aggregate", self.collection.clone());
                cmd.insert("pipeline", stages);
                let mut cursor = Document::new();
                if let Some(fetch) = fetch {
                    cursor.insert("batchSize", fetch);
                }
                cmd.insert("cursor", cursor);
            }
            Op::Count { filter } => {
                let mut match_stage = Document::new();
                match_stage.insert("$match", filter.clone());
                let mut group = Document::new();
                group.insert("_id", Bson::Null);
                let mut sum = Document::new();
                sum.insert("$sum", 1_i32);
                group.insert("count", sum);
                let mut group_stage = Document::new();
                group_stage.insert("$group", group);
                let mut project = Document::new();
                project.insert("_id", 0_i32);
                let mut project_stage = Document::new();
                project_stage.insert("$project", project);
                cmd.insert("aggregate", self.collection.clone());
                cmd.insert(
                    "pipeline",
                    vec![
                        Bson::Document(match_stage),
                        Bson::Document(group_stage),
                        Bson::Document(project_stage),
                    ],
                );
                cmd.insert("cursor", Document::new());
            }
            // `distinct` is run as an AGGREGATION, not as the `distinct`
            // command: that command takes no limit at all, so 500 distinct
            // values crossed the network for a `--limit 3` (measured) and the
            // only ceiling was the 16 MiB reply cap. The pipeline honors the
            // row limit like every other read. `$unwind` keeps the command's
            // array semantics (distinct returns the ELEMENTS of an array
            // field), and `$sort` makes a truncated answer deterministic.
            Op::Distinct { key, filter } => {
                let field = format!("${key}");
                let mut match_stage = Document::new();
                match_stage.insert("$match", filter.clone());
                let mut unwind = Document::new();
                unwind.insert("path", field.clone());
                unwind.insert("preserveNullAndEmptyArrays", true);
                let mut unwind_stage = Document::new();
                unwind_stage.insert("$unwind", unwind);
                let mut group = Document::new();
                group.insert("_id", field);
                let mut group_stage = Document::new();
                group_stage.insert("$group", group);
                let mut sort = Document::new();
                sort.insert("_id", 1_i32);
                let mut sort_stage = Document::new();
                sort_stage.insert("$sort", sort);
                let mut pipeline = vec![
                    Bson::Document(match_stage),
                    Bson::Document(unwind_stage),
                    Bson::Document(group_stage),
                    Bson::Document(sort_stage),
                ];
                if let Some(fetch) = fetch {
                    let mut limit_stage = Document::new();
                    limit_stage.insert("$limit", fetch);
                    pipeline.push(Bson::Document(limit_stage));
                }
                cmd.insert("aggregate", self.collection.clone());
                cmd.insert("pipeline", pipeline);
                let mut cursor = Document::new();
                if let Some(fetch) = fetch {
                    cursor.insert("batchSize", fetch);
                }
                cmd.insert("cursor", cursor);
            }
        }
        cmd.insert("maxTimeMS", max_time);
        cmd
    }

    /// The `explain` of the command [`command`](Self::command) would run —
    /// same collection, same filter, same pipeline, same `.sort()`/`.skip()`
    /// and the agent's own `.limit(n)`.
    ///
    /// **Deliberately NOT the same bounds:** nyet's own row limit is left out
    /// (`command(None, ..)`). It is how the ANSWER is cut, not part of the
    /// query the agent wrote, and inside a plan it would show up as a `LIMIT`
    /// stage carrying a number the agent never chose. The plan is therefore
    /// the un-limited — that is, the worst-case — shape of the read.
    ///
    /// **`verbosity` is hard-coded to `queryPlanner`, and this is the security
    /// property of the whole command:** `executionStats` and
    /// `allPlansExecution` RUN the query (measured: a pipeline that took 1 ms
    /// in `queryPlanner` ran for 4 s in `executionStats`), so `explain` would
    /// otherwise be a way to execute a statement while calling it "just a
    /// plan". Nothing in the agent's input can reach this field: nyet builds
    /// the whole document, and the parser refuses an options document anyway.
    ///
    /// `maxTimeMS` rides on the OUTER document, where it bounds the explain
    /// itself — the inner command is the thing being described, not run.
    pub fn explain_command(&self, max_time_ms: u64) -> Document {
        let mut inner = self.command(None, max_time_ms);
        inner.remove("maxTimeMS");
        let mut cmd = Document::new();
        cmd.insert("explain", inner);
        cmd.insert("verbosity", "queryPlanner");
        cmd.insert("maxTimeMS", i32::try_from(max_time_ms).unwrap_or(i32::MAX));
        cmd
    }

    /// The reply -> columns, rows, and whether the SERVER stopped early.
    /// Documents have no fixed shape, so the
    /// columns are the union of the TOP-LEVEL field names in first-seen order
    /// and a document missing one gets a JSON null there; nested values stay
    /// nested JSON (exactly how a PostgreSQL `jsonb` column already arrives), so
    /// `--format table`/`csv` render them as compact JSON rather than refusing.
    ///
    /// Values are relaxed extended JSON: an ObjectId reads `{"$oid": "..."}`,
    /// a date `{"$date": "..."}` — the same spelling that can be pasted back
    /// into the next filter.
    pub fn read_reply(&self, reply: Document) -> Result<Reply, String> {
        let Some(cursor) = reply.get("cursor").and_then(Bson::as_document) else {
            return Err("the server's reply carries no `cursor` document".to_string());
        };
        let Some(Bson::Array(docs)) = cursor.get("firstBatch") else {
            return Err("the server's reply carries no `cursor.firstBatch`".to_string());
        };
        // A cursor the server left OPEN means it stopped early — it cuts a
        // batch at 16 MiB before it reaches the limit nyet asked for. Without
        // this the answer was silently incomplete and reported `truncated:
        // false`, which is the worst thing a read tool can do (UX-1).
        let truncated = !matches!(cursor.get("id"), Some(Bson::Int64(0)) | None);
        // countDocuments over an empty collection produces NO group, which is a
        // count of zero — not a missing answer.
        if matches!(self.op, Op::Count { .. }) && docs.is_empty() {
            return Ok(Reply {
                columns: vec!["count".to_string()],
                rows: vec![vec![serde_json::json!(0)]],
                truncated,
            });
        }
        // `distinct` is an aggregation here, so its values arrive as
        // `{_id: <value>}` documents; present them as one plain column.
        if matches!(self.op, Op::Distinct { .. }) {
            let mut rows = Vec::new();
            for doc in docs {
                let Bson::Document(doc) = doc else {
                    return Err("the server returned a result that is not a document".to_string());
                };
                let value = doc.get("_id").cloned().unwrap_or(Bson::Null);
                rows.push(vec![value.into_relaxed_extjson()]);
            }
            return Ok(Reply {
                columns: vec!["value".to_string()],
                rows,
                truncated,
            });
        }
        let mut columns: Vec<String> = Vec::new();
        let mut named: Vec<Vec<(String, serde_json::Value)>> = Vec::new();
        for doc in docs {
            let Bson::Document(doc) = doc else {
                return Err("the server returned a result that is not a document".to_string());
            };
            let mut row: Vec<(String, serde_json::Value)> = Vec::new();
            for (key, value) in doc.clone() {
                if !columns.contains(&key) {
                    columns.push(key.clone());
                }
                row.push((key, value.into_relaxed_extjson()));
            }
            named.push(row);
        }
        let rows = align(&columns, named);
        Ok(Reply {
            columns,
            rows,
            truncated,
        })
    }
}

/// What one reply became: the rows, and whether the server cut them short of
/// what nyet asked for (a 16 MiB batch cap reached before the row limit).
#[derive(Debug)]
pub struct Reply {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<serde_json::Value>>,
    /// The server left its cursor open, so there IS more — the agent must not
    /// read this answer as complete.
    pub truncated: bool,
}

/// Rows arrive as (name, value) pairs because each document may carry a
/// different set of fields; this puts them in the column order the envelope
/// promises, filling absent fields with null.
fn align(
    columns: &[String],
    rows: Vec<Vec<(String, serde_json::Value)>>,
) -> Vec<Vec<serde_json::Value>> {
    rows.into_iter()
        .map(|row| {
            columns
                .iter()
                .map(|c| {
                    row.iter()
                        .find(|(k, _)| k == c)
                        .map(|(_, v)| v.clone())
                        .unwrap_or(serde_json::Value::Null)
                })
                .collect()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn deny(text: &str) -> Refusal {
        match check(text) {
            Err(r) => r,
            Ok(request) => panic!("{text:?} was allowed: {request:?}"),
        }
    }

    fn allow(text: &str) -> Request {
        match check(text) {
            Ok(request) => request,
            Err(r) => panic!("{text:?} was refused: {} / {}", r.reason, r.message),
        }
    }

    /// `binary_search` is only a search on a SORTED list; an entry out of order
    /// would be invisible to it — a false REFUSAL for an operator that is on
    /// the list, and (worse, if the pair were reversed) a gap.
    #[test]
    fn lists_are_sorted_and_disjoint_where_they_must_be() {
        for (name, list) in [
            ("ALLOWED_METHODS", ALLOWED_METHODS),
            ("WRITE_METHODS", WRITE_METHODS),
            ("JS_METHODS", JS_METHODS),
            ("ALLOWED_CHAIN", ALLOWED_CHAIN),
            ("STAGES", STAGES),
            ("OPS", OPS),
            ("WRITE_KEYS", WRITE_KEYS),
            ("JS_KEYS", JS_KEYS),
            ("NYET_OWNED", NYET_OWNED),
            ("EXT_JSON_KEYS", EXT_JSON_KEYS),
            ("NAMESPACE_STAGES", NAMESPACE_STAGES),
        ] {
            let mut sorted = list.to_vec();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(sorted, list.to_vec(), "{name} is not sorted/deduplicated");
        }
        // A stage that names a collection must BE a stage, or
        // `check_collection_source` would be guarding something that can never
        // reach it (and the `system.*` rule would quietly stop applying).
        for stage in NAMESPACE_STAGES {
            assert!(STAGES.contains(stage), "{stage} is not a stage");
        }
        // The refusal lists must never overlap the allowlists, or the allowlist
        // would win somewhere and the deny would be decoration.
        for bad in WRITE_KEYS.iter().chain(JS_KEYS).chain(NYET_OWNED) {
            assert!(!STAGES.contains(bad), "{bad} is both refused and a stage");
            assert!(!OPS.contains(bad), "{bad} is both refused and an operator");
        }
        for bad in WRITE_METHODS.iter().chain(JS_METHODS) {
            assert!(
                !ALLOWED_METHODS.contains(bad),
                "{bad} is both refused and allowed"
            );
        }
    }

    /// The three reasons MongoDB shares with the SQL validator must stay the
    /// SAME strings: they are one closed list in the contract (Д7), and an
    /// agent that learned `WRITE_OPERATION` from Postgres must recognize it
    /// here.
    #[test]
    fn shared_reason_codes_match_the_sql_validator() {
        use crate::validator::DenyReason;
        assert_eq!(PARSE_FAILED, DenyReason::ParseFailed.as_str());
        assert_eq!(WRITE_OPERATION, DenyReason::WriteOperation.as_str());
        assert_eq!(DENIED_FUNCTION, DenyReason::DeniedFunction.as_str());
    }

    /// Golden corpus (Д6) — the public specification of what MongoDB layer 1
    /// accepts. Lives in `tests/corpus/mongo/` (a SUBdirectory, so the SQL
    /// corpus runner, which reads `tests/corpus/*.yaml`, does not try to parse
    /// mongosh with sqlparser) and uses the same tiny line format.
    #[test]
    fn golden_corpus() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/mongo");
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
            let mut cases: Vec<(usize, String, String, Option<String>)> = Vec::new();
            for (idx, raw) in text.lines().enumerate() {
                let line = raw.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Some(q) = line.strip_prefix("- query: ") {
                    cases.push((idx + 1, q.to_string(), String::new(), None));
                    continue;
                }
                let case = cases
                    .last_mut()
                    .unwrap_or_else(|| panic!("{name}:{}: key before first '- query:'", idx + 1));
                if let Some(v) = line.strip_prefix("verdict: ") {
                    case.2 = v.to_string();
                } else if let Some(r) = line.strip_prefix("reason: ") {
                    case.3 = Some(r.to_string());
                } else {
                    panic!("{name}:{}: unrecognized corpus line: {raw}", idx + 1);
                }
            }
            for (line, query, verdict, reason) in cases {
                total += 1;
                let at = format!("{name}:{line} {query:?}");
                match check(&query) {
                    Ok(_) => {
                        assert_eq!(verdict, "allow", "{at}: got allow");
                        assert!(reason.is_none(), "{at}: reason on an allow case");
                    }
                    Err(r) => {
                        assert_eq!(verdict, "deny", "{at}: got deny ({})", r.message);
                        assert_eq!(reason.as_deref(), Some(r.reason), "{at}: wrong reason");
                        // Д10: a refusal without an actionable hint does not ship.
                        assert!(!r.message.is_empty(), "{at}: empty message");
                        assert!(!r.hint.is_empty(), "{at}: empty hint");
                    }
                }
            }
        }
        // Tripwire against accidental corpus loss.
        assert!(total >= 220, "corpus suspiciously small: {total} cases");
    }

    /// Д3: the parser sits on untrusted input, so NOTHING may panic — not
    /// truncation at every byte boundary, not random punctuation, not a
    /// thousand nested braces (which without the depth limit would overflow
    /// the stack, and an abort is not a refusal).
    #[test]
    fn no_input_can_panic() {
        let seeds = [
            "",
            " ",
            "\n\t",
            "db",
            "db.",
            "db..",
            "db.c.find(",
            "db.c.find({",
            "db.c.find({a:",
            "db.c.find({a:1},",
            "db.c.find(/",
            "db.c.find(\"",
            "db.c.find('",
            "db.c.find({a: ObjectId(",
            "db.c.find({a: \\u",
            "db.c.find({a: \"\\u00\"})",
            "db.c.aggregate([{",
            "db.c.aggregate([[[[",
            "{}[]()\"'/\\,:;.$",
            "db.c.find({$where:",
            "日本語",
            "db.日本.find({})",
            "db.c.find({a: 1e999})",
            "db.c.find({a: 99999999999999999999999999})",
            "db.c.find({a: -})",
            "db.c.find({a: 1}).limit(99999999999999999999)",
        ];
        for seed in seeds {
            // Every prefix of every seed, so a truncation inside any token is
            // covered rather than only at the end.
            for cut in 0..=seed.chars().count() {
                let prefix: String = seed.chars().take(cut).collect();
                let _ = check(&prefix);
            }
        }
        // Deep nesting, both shapes, well past the limit: a refusal, not a
        // stack overflow.
        for (open, close) in [("{a:", "}"), ("[", "]"), ("NumberLong(", ")")] {
            let deep = format!("db.c.find({}1{})", open.repeat(5000), close.repeat(5000));
            assert_eq!(deny(&deep).reason, PARSE_FAILED, "{open}");
        }
        // An oversized input is refused before it is even scanned — and the
        // ceiling is in BYTES, so a multi-byte character cannot buy four times
        // the advertised size.
        let huge = format!("db.c.find({{a: \"{}\"}})", "x".repeat(MAX_INPUT_BYTES));
        assert_eq!(deny(&huge).reason, PARSE_FAILED);
        let huge_utf8 = format!(
            "db.c.find({{a: \"{}\"}})",
            "\u{1F600}".repeat(MAX_INPUT_BYTES / 4)
        );
        assert!(
            huge_utf8.chars().count() < MAX_INPUT_BYTES,
            "must pass a CHAR count"
        );
        assert_eq!(deny(&huge_utf8).reason, PARSE_FAILED);
    }

    /// The parser is the only thing that decides what runs, so what it produced
    /// has to be exactly what was written — types included.
    #[test]
    fn values_keep_their_bson_type() {
        let Op::Find { filter, .. } = allow(
            "db.c.find({s: \"x\", i: 7, big: 9007199254740993, d: 1.5, b: true, n: null, \
             oid: ObjectId(\"66210f0e2f1a4b0012a3c4d5\"), when: ISODate(\"2026-01-31T00:00:00Z\"), \
             dec: NumberDecimal(\"19.99\"), arr: [1, \"two\"], sub: {k: 1}})",
        )
        .op
        else {
            panic!("not a find")
        };
        assert!(matches!(filter.get("s"), Some(Bson::String(s)) if s == "x"));
        assert!(matches!(filter.get("i"), Some(Bson::Int32(7))));
        assert!(matches!(
            filter.get("big"),
            Some(Bson::Int64(9007199254740993))
        ));
        assert!(matches!(filter.get("d"), Some(Bson::Double(_))));
        assert!(matches!(filter.get("b"), Some(Bson::Boolean(true))));
        assert!(matches!(filter.get("n"), Some(Bson::Null)));
        assert!(matches!(filter.get("oid"), Some(Bson::ObjectId(_))));
        assert!(matches!(filter.get("when"), Some(Bson::DateTime(_))));
        assert!(matches!(filter.get("dec"), Some(Bson::Decimal128(_))));
        assert!(matches!(filter.get("arr"), Some(Bson::Array(a)) if a.len() == 2));
        assert!(matches!(filter.get("sub"), Some(Bson::Document(_))));

        // Extended JSON in value position resolves to the SAME native types as
        // the constructors — the classifier never sees a `$oid` key at all.
        let Op::Find { filter, .. } = allow(
            "db.c.find({oid: {\"$oid\": \"66210f0e2f1a4b0012a3c4d5\"}, \
             when: {\"$date\": \"2026-01-31T00:00:00Z\"}})",
        )
        .op
        else {
            panic!("not a find")
        };
        assert!(matches!(filter.get("oid"), Some(Bson::ObjectId(_))));
        assert!(matches!(filter.get("when"), Some(Bson::DateTime(_))));

        // A Timestamp survives the round trip: what a result prints is what the
        // next filter accepts.
        let Op::Find { filter, .. } =
            allow("db.c.find({ts: {\"$timestamp\": {\"t\": 7, \"i\": 2}}})").op
        else {
            panic!("not a find")
        };
        assert!(matches!(
            filter.get("ts"),
            Some(Bson::Timestamp(t)) if t.time == 7 && t.increment == 2
        ));

        // A regex literal keeps its pattern and its (sorted) options.
        let Op::Find { filter, .. } = allow("db.c.find({n: /^a\\/b[/]c/mi})").op else {
            panic!("not a find")
        };
        let Some(Bson::RegularExpression(re)) = filter.get("n") else {
            panic!("not a regex: {filter:?}")
        };
        assert_eq!(re.pattern, "^a\\/b[/]c");
        assert_eq!(re.options, "im");
    }

    /// The wire command is nyet's, not the agent's: the row limit, the batch
    /// size, `singleBatch` and `maxTimeMS` are set here and nowhere else, and
    /// an agent's own `.limit()` can only LOWER the effective limit.
    #[test]
    fn the_command_carries_nyets_own_bounds() {
        let cmd = allow("db.users.find({a: 1})").command(Some(1001), 30_000);
        assert_eq!(cmd.get_str("find").unwrap(), "users");
        assert_eq!(cmd.get_i64("limit").unwrap(), 1001);
        // batchSize, NOT singleBatch: singleBatch closes the cursor whatever
        // happened, which hid a 16 MiB batch cut (see read_reply).
        assert_eq!(cmd.get_i64("batchSize").unwrap(), 1001);
        assert!(!cmd.contains_key("singleBatch"));
        assert_eq!(cmd.get_i32("maxTimeMS").unwrap(), 30_000);

        // The agent asked for fewer rows than nyet allows: its number wins.
        let cmd = allow("db.users.find({}).limit(5)").command(Some(1001), 1000);
        assert_eq!(cmd.get_i64("limit").unwrap(), 5);
        // ... and asking for more than nyet allows does NOT raise the ceiling.
        let cmd = allow("db.users.find({}).limit(500000)").command(Some(1001), 1000);
        assert_eq!(cmd.get_i64("limit").unwrap(), 1001);
        // findOne is a find with limit 1.
        let cmd = allow("db.users.findOne({})").command(Some(1001), 1000);
        assert_eq!(cmd.get_i64("limit").unwrap(), 1);

        // An aggregation gets the limit as a trailing stage plus a batch size
        // that keeps the reply to ONE round trip with a closed cursor.
        let cmd = allow("db.users.aggregate([{$match: {a: 1}}])").command(Some(11), 5000);
        let pipeline = cmd.get_array("pipeline").unwrap();
        assert_eq!(pipeline.len(), 2);
        assert_eq!(
            pipeline[1]
                .as_document()
                .unwrap()
                .get_i64("$limit")
                .unwrap(),
            11
        );
        assert_eq!(
            cmd.get_document("cursor")
                .unwrap()
                .get_i64("batchSize")
                .unwrap(),
            11
        );

        // countDocuments is an aggregation, like mongosh's own implementation.
        let cmd = allow("db.users.countDocuments({a: 1})").command(Some(11), 5000);
        assert_eq!(cmd.get_str("aggregate").unwrap(), "users");
        assert_eq!(cmd.get_array("pipeline").unwrap().len(), 3);

        // distinct is a BOUNDED aggregation, not the `distinct` command: that
        // command takes no limit at all, so the whole distinct set crossed the
        // network however small --limit was.
        let cmd = allow("db.users.distinct(\"status\", {a: 1})").command(Some(11), 5000);
        assert_eq!(cmd.get_str("aggregate").unwrap(), "users");
        assert!(!cmd.contains_key("distinct"));
        let pipeline = cmd.get_array("pipeline").unwrap();
        assert_eq!(
            pipeline
                .last()
                .and_then(Bson::as_document)
                .and_then(|d| d.get_i64("$limit").ok()),
            Some(11)
        );
        assert_eq!(
            cmd.get_document("cursor")
                .unwrap()
                .get_i64("batchSize")
                .unwrap(),
            11
        );
    }

    /// Documents have no fixed shape, so the columns are the UNION of the
    /// top-level field names and a document missing one gets null — never a
    /// shifted row.
    #[test]
    fn the_reply_becomes_columns_and_rows() {
        let batch = |docs: Vec<mongodb::bson::Bson>, id: i64| {
            mongodb::bson::doc! {
                "cursor": { "id": id, "ns": "app.users", "firstBatch": docs },
                "ok": 1.0,
            }
        };
        let request = allow("db.users.find({})");
        let reply = request
            .read_reply(batch(
                vec![
                    mongodb::bson::bson!({ "_id": 1_i32, "name": "a", "tags": ["x"] }),
                    mongodb::bson::bson!({ "_id": 2_i32, "extra": { "nested": true } }),
                ],
                0,
            ))
            .unwrap();
        assert_eq!(reply.columns, vec!["_id", "name", "tags", "extra"]);
        assert_eq!(reply.rows.len(), 2);
        assert_eq!(reply.rows[0][1], serde_json::json!("a"));
        // A field the second document does not have reads as null, not as a
        // shifted value.
        assert_eq!(reply.rows[1][1], serde_json::Value::Null);
        // Nested values stay nested JSON (table/csv render them as JSON text,
        // exactly like a PostgreSQL jsonb column).
        assert!(reply.rows[1][3].is_object());
        assert!(!reply.truncated);

        // A cursor the server left OPEN means it stopped early — it cuts a
        // batch at 16 MiB before reaching the limit nyet asked for, and the
        // row count alone cannot show that. Reporting this as complete is the
        // bug this assertion exists for.
        let reply = request
            .read_reply(batch(
                vec![mongodb::bson::bson!({ "_id": 1_i32 })],
                4_242_424_242,
            ))
            .unwrap();
        assert!(reply.truncated, "an open cursor means there is more");

        // distinct is an aggregation here, so its values arrive as {_id: v}
        // documents and are presented as one plain column.
        let request = allow("db.users.distinct(\"status\")");
        let reply = request
            .read_reply(batch(
                vec![
                    mongodb::bson::bson!({ "_id": "new" }),
                    mongodb::bson::bson!({ "_id": "paid" }),
                ],
                0,
            ))
            .unwrap();
        assert_eq!(reply.columns, vec!["value"]);
        assert_eq!(
            reply.rows,
            vec![
                vec![serde_json::json!("new")],
                vec![serde_json::json!("paid")]
            ]
        );

        // An empty collection counts as zero rather than as "no answer".
        let request = allow("db.users.countDocuments({})");
        let reply = request.read_reply(batch(Vec::new(), 0)).unwrap();
        assert_eq!(reply.columns, vec!["count"]);
        assert_eq!(reply.rows, vec![vec![serde_json::json!(0)]]);

        // A reply nyet cannot read is an error, never a panic and never an
        // empty result that would read as "no rows".
        assert!(allow("db.users.find({})")
            .read_reply(mongodb::bson::doc! { "ok": 1.0 })
            .is_err());

        // An ObjectId comes back in the spelling that can be pasted into the
        // next filter.
        let reply = allow("db.users.find({})")
            .read_reply(batch(
                vec![mongodb::bson::bson!({
                    "_id": mongodb::bson::oid::ObjectId::parse_str("66210f0e2f1a4b0012a3c4d5").unwrap()
                })],
                0,
            ))
            .unwrap();
        assert_eq!(
            reply.rows[0][0],
            serde_json::json!({ "$oid": "66210f0e2f1a4b0012a3c4d5" })
        );
    }

    /// The allowlist is the security boundary, so the walk has to reach EVERY
    /// nesting level — the corpus pins the cases, this pins the property.
    #[test]
    fn an_unknown_dollar_key_is_refused_at_any_depth() {
        let mut filter = "{$newOperator: 1}".to_string();
        for _ in 0..20 {
            filter = format!("{{a: {{$elemMatch: {filter}}}}}");
            let r = deny(&format!("db.c.find({filter})"));
            assert_eq!(r.reason, DENIED_OPERATOR, "{filter}");
        }
        // ... and inside every pipeline-carrying stage.
        for shape in [
            "db.c.aggregate([{$lookup: {from: \"o\", as: \"o\", pipeline: [{$newStage: {}}]}}])",
            "db.c.aggregate([{$unionWith: {coll: \"o\", pipeline: [{$newStage: {}}]}}])",
            "db.c.aggregate([{$facet: {a: [{$newStage: {}}]}}])",
            "db.c.aggregate([{$graphLookup: {from: \"o\", restrictSearchWithMatch: {$newOp: 1}}}])",
            "db.c.aggregate([{$project: {x: {$newOp: 1}}}])",
            "db.c.aggregate([{$group: {_id: null, x: {$newOp: 1}}}])",
        ] {
            assert_eq!(deny(shape).reason, DENIED_OPERATOR, "{shape}");
        }
    }
}
