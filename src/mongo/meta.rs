//! MongoDB metadata: turning the server's replies to `listCollections`,
//! `listIndexes`, `$collStats`, `$sample`, `explain` and `connectionStatus`
//! into the answers `nyet schema` / `explain` / `doctor` publish.
//!
//! Pure (Д1/Д2) — documents in, contract structures out, no IO — so every
//! reply shape below is unit-tested without a server, including the shapes a
//! healthy server never sends (empty, truncated, missing a field, the wrong
//! type). The engine does nothing here but the round trips.
//!
//! The honesty rule of this module (UX-7, UX-1): **MongoDB has no schema**, so
//! nothing here may present an inference as one. Every field nyet inferred
//! carries `source = "sample"` and the number of documents it was seen in;
//! only a field the collection's own `$jsonSchema` validator declares — a rule
//! the SERVER enforces on every write — is allowed to say `source =
//! "validator"`.

use crate::output::{
    build_table, Grants, JsFact, KeyPart, SchemaColumn, SchemaIndex, SchemaTable, SuperuserFact,
};
use mongodb::bson::{Bson, Document};
use serde_json::Value;
use std::collections::BTreeMap;

/// How many documents `nyet schema <alias> <collection>` samples.
///
/// One batch, one round trip, and enough that a field present in 3% of the
/// collection is usually seen at least once — while a bigger sample would cost
/// the agent tokens for fields it will meet once a year. Deliberately NOT
/// configurable (Д5, like `output::DETAIL_LIMIT`): the escape hatch is a
/// query, which is honest about what it is —
/// `nyet query <alias> 'db.<c>.aggregate([{$sample: {size: 1000}}])'`.
pub const SAMPLE_SIZE: u32 = 100;

/// Most fields one collection's answer may list. A schemaless collection can
/// hold thousands of distinct keys (the "field names are user ids" pattern),
/// and dumping them would burn the agent's context (UX-4). The rarest go
/// first, and the rule is stated in the `SCHEMA_SAMPLED` warning so a full list
/// of exactly this length is never mistaken for the whole truth.
pub const MAX_FIELDS: usize = 100;

/// How deep a dotted path goes (`profile.address.city` = 3). Deeper structure
/// is still visible — the leaf's type reads `object` — but is not enumerated.
const MAX_PATH_SEGMENTS: usize = 3;

/// Bound on every recursive walk over a server reply (Д3: no input, however
/// odd, may exhaust the stack).
const MAX_DEPTH: usize = 50;

// ---------------------------------------------------------------------------
// nyet schema
// ---------------------------------------------------------------------------

/// One entry of a `listCollections` reply: the name and what it is.
pub struct CollectionInfo {
    pub name: String,
    /// `"collection"` or `"view"` — the payload's `kind`.
    pub kind: &'static str,
    /// The collection's `options` document, when the reply carried one (only
    /// the full `listCollections`, not the `nameOnly` fallback). The declared
    /// `$jsonSchema` lives in `options.validator`.
    pub options: Option<Document>,
}

/// `listCollections` -> the objects nyet will talk about.
///
/// `system.*` is dropped for the same reason layer 1 refuses to read it: those
/// catalogs hold stored JavaScript, view definitions and profiler output. A
/// cursor the server left OPEN is an ERROR rather than a silent short list —
/// "these are your collections" must never be a partial answer (UX-1).
pub fn collections(reply: &Document) -> Result<Vec<CollectionInfo>, String> {
    let Some(cursor) = reply.get("cursor").and_then(Bson::as_document) else {
        return Err("the server's listCollections reply carries no `cursor` document".to_string());
    };
    if !matches!(cursor.get("id"), Some(Bson::Int64(0)) | None) {
        return Err(
            "the server returned only part of the collection list (it left the cursor open); \
             nyet reads one batch, so it cannot promise this list is complete"
                .to_string(),
        );
    }
    let Some(Bson::Array(batch)) = cursor.get("firstBatch") else {
        return Err(
            "the server's listCollections reply carries no `cursor.firstBatch`".to_string(),
        );
    };
    let mut out = Vec::new();
    for entry in batch {
        let Some(doc) = entry.as_document() else {
            continue;
        };
        let Some(name) = doc.get_str("name").ok() else {
            continue;
        };
        if name.starts_with("system.") {
            continue;
        }
        out.push(CollectionInfo {
            name: name.to_string(),
            kind: if doc.get_str("type") == Ok("view") {
                "view"
            } else {
                "collection"
            },
            options: doc.get("options").and_then(Bson::as_document).cloned(),
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// The names-only answer for `nyet schema <alias>`: MongoDB cannot describe a
/// collection without sampling it, and sampling every collection of a database
/// would be one round trip per collection per aspect. So the listing lists, and
/// the agent asks for the one it cares about (the cli's `SCHEMA_TRUNCATED`
/// warning says exactly that).
pub fn listing(objects: Vec<CollectionInfo>) -> Vec<SchemaTable> {
    objects
        .into_iter()
        .map(|c| SchemaTable {
            name: c.name,
            kind: c.kind,
            ..SchemaTable::default()
        })
        .collect()
}

/// One collection's answer: the declared validator (if the role could read it)
/// and the sampled documents, through the same pk/unique folding every engine
/// uses.
pub fn table(
    name: String,
    kind: &'static str,
    options: Option<&Document>,
    sample: &[Document],
    indexes: Vec<SchemaIndex>,
    count: Option<u64>,
) -> SchemaTable {
    let sampled = u32::try_from(sample.len()).unwrap_or(u32::MAX);
    let columns = columns(options.and_then(json_schema), sample, sampled);
    // `_id` is the one field MongoDB itself guarantees: always present, always
    // unique, never null. Marking it as the key is a fact, not an inference.
    let pk = if columns.iter().any(|c| c.name == "_id") {
        vec!["_id".to_string()]
    } else {
        Vec::new()
    };
    let mut table = build_table(name, kind, columns, &pk, indexes, Vec::new(), true);
    table.count = count;
    table.sampled = Some(sampled);
    table
}

/// The declared `$jsonSchema` of a collection, if it has one. A validator can
/// also be a plain query expression (`{email: {$exists: true}}`); that is not a
/// schema and is not read as one.
fn json_schema(options: &Document) -> Option<&Document> {
    options
        .get("validator")
        .and_then(Bson::as_document)?
        .get("$jsonSchema")
        .and_then(Bson::as_document)
}

/// What one sampled document said about one path.
#[derive(Default)]
struct Observed {
    types: Vec<&'static str>,
    seen: u32,
}

/// The fields, merged from the two sources and sorted by path — which puts a
/// sub-document's own line (`profile`) right before its children
/// (`profile.city`).
fn columns(schema: Option<&Document>, sample: &[Document], sampled: u32) -> Vec<SchemaColumn> {
    let mut observed: BTreeMap<String, Observed> = BTreeMap::new();
    for doc in sample {
        // Per DOCUMENT first: an array of sub-documents mentions the same path
        // many times, and `seen` counts documents, not occurrences.
        let mut here: BTreeMap<String, Vec<&'static str>> = BTreeMap::new();
        walk_document(doc, "", 1, &mut here);
        for (path, types) in here {
            let entry = observed.entry(path).or_default();
            entry.seen += 1;
            for ty in types {
                if !entry.types.contains(&ty) {
                    entry.types.push(ty);
                }
            }
        }
    }
    let mut declared: BTreeMap<String, SchemaColumn> = BTreeMap::new();
    if let Some(schema) = schema {
        declare(schema, "", 1, &mut declared);
    }
    // Rarest first out: a cap that silently kept the alphabetically-first
    // fields would hide the ones the agent is most likely to need.
    let mut ranked: Vec<(&String, &Observed)> = observed.iter().collect();
    ranked.sort_by(|a, b| b.1.seen.cmp(&a.1.seen).then_with(|| a.0.cmp(b.0)));
    ranked.truncate(MAX_FIELDS.saturating_sub(declared.len()));
    let kept: Vec<String> = ranked.into_iter().map(|(path, _)| path.clone()).collect();

    let mut columns: BTreeMap<String, SchemaColumn> = BTreeMap::new();
    for (path, column) in declared {
        // A declared field the documents do NOT all carry: the validator only
        // ever applied to writes made after it existed, so this disagreement is
        // a real property of the data and is reported as such.
        let mut column = column;
        if let Some(o) = observed.get(&path) {
            column.seen = Some(o.seen);
            column.nullable = column.nullable || o.seen < sampled;
        }
        columns.insert(path, column);
    }
    for path in kept {
        if columns.contains_key(&path) {
            continue;
        }
        let Some(o) = observed.get(&path) else {
            continue;
        };
        let mut types = o.types.clone();
        types.sort_unstable();
        columns.insert(
            path.clone(),
            SchemaColumn {
                name: path,
                ty: types.join("|"),
                // Absent from some sampled document, or explicitly null in one.
                nullable: o.seen < sampled || o.types.contains(&"null"),
                source: Some("sample"),
                seen: Some(o.seen),
                ..SchemaColumn::default()
            },
        );
    }
    columns.into_values().collect()
}

/// Every path of one document, with the BSON type names seen at it. Array
/// elements are folded into the array's own path (`items.sku`), which is how
/// MongoDB itself addresses them in a query.
fn walk_document(
    doc: &Document,
    prefix: &str,
    depth: usize,
    out: &mut BTreeMap<String, Vec<&'static str>>,
) {
    if depth > MAX_PATH_SEGMENTS || depth > MAX_DEPTH {
        return;
    }
    for (key, value) in doc {
        let path = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };
        let types = out.entry(path.clone()).or_default();
        let ty = type_name(value);
        if !types.contains(&ty) {
            types.push(ty);
        }
        match value {
            Bson::Document(sub) => walk_document(sub, &path, depth + 1, out),
            Bson::Array(items) => {
                for item in items {
                    if let Bson::Document(sub) = item {
                        walk_document(sub, &path, depth + 1, out);
                    }
                }
            }
            _ => {}
        }
    }
}

/// The `$jsonSchema` properties, recursively. `required` is the validator's own
/// word for "not null"; a `bsonType` list that includes `"null"` is the other
/// half.
fn declare(
    schema: &Document,
    prefix: &str,
    depth: usize,
    out: &mut BTreeMap<String, SchemaColumn>,
) {
    if depth > MAX_PATH_SEGMENTS || depth > MAX_DEPTH {
        return;
    }
    let required: Vec<&str> = schema
        .get("required")
        .and_then(Bson::as_array)
        .map(|a| a.iter().filter_map(Bson::as_str).collect())
        .unwrap_or_default();
    let Some(properties) = schema.get("properties").and_then(Bson::as_document) else {
        return;
    };
    for (key, value) in properties {
        let Some(sub) = value.as_document() else {
            continue;
        };
        let path = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };
        let types = declared_types(sub);
        out.insert(
            path.clone(),
            SchemaColumn {
                name: path.clone(),
                ty: if types.is_empty() {
                    "any".to_string()
                } else {
                    types.join("|")
                },
                nullable: !required.contains(&key.as_str()) || types.iter().any(|t| t == "null"),
                source: Some("validator"),
                ..SchemaColumn::default()
            },
        );
        declare(sub, &path, depth + 1, out);
        // An array of sub-documents: `items` describes the elements, which
        // MongoDB addresses under the array's own path.
        if let Some(items) = sub.get("items").and_then(Bson::as_document) {
            declare(items, &path, depth + 1, out);
        }
    }
}

fn declared_types(property: &Document) -> Vec<String> {
    // `bsonType` is MongoDB's own spelling; `type` is the JSON Schema keyword,
    // which $jsonSchema also accepts.
    let value = property
        .get("bsonType")
        .or_else(|| property.get("type"))
        .cloned();
    match value {
        Some(Bson::String(s)) => vec![s],
        Some(Bson::Array(items)) => items
            .iter()
            .filter_map(|i| i.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

/// The BSON type name as `{$type: "..."}` spells it — so a type in the answer
/// can be pasted straight into the next filter.
fn type_name(value: &Bson) -> &'static str {
    match value {
        Bson::Double(_) => "double",
        Bson::String(_) => "string",
        Bson::Array(_) => "array",
        Bson::Document(_) => "object",
        Bson::Boolean(_) => "bool",
        Bson::Null => "null",
        Bson::RegularExpression(_) => "regex",
        Bson::JavaScriptCode(_) => "javascript",
        Bson::JavaScriptCodeWithScope(_) => "javascriptWithScope",
        Bson::Int32(_) => "int",
        Bson::Int64(_) => "long",
        Bson::Timestamp(_) => "timestamp",
        Bson::Binary(_) => "binData",
        Bson::ObjectId(_) => "objectId",
        Bson::DateTime(_) => "date",
        Bson::Symbol(_) => "symbol",
        Bson::Decimal128(_) => "decimal",
        Bson::Undefined => "undefined",
        Bson::MaxKey => "maxKey",
        Bson::MinKey => "minKey",
        Bson::DbPointer(_) => "dbPointer",
    }
}

/// `listIndexes` -> the index entries. The `_id_` index is dropped: `_id` is
/// already marked as the key, exactly as the SQL engines drop the index backing
/// a PRIMARY KEY.
///
/// `unique` is kept ONLY for an index that enforces uniqueness unconditionally:
/// a `partialFilterExpression` or a `sparse` index is unique for some documents
/// only, and folding that into a column flag would be a promise the database
/// does not make.
pub fn indexes(reply: &Document) -> Vec<SchemaIndex> {
    let Some(Bson::Array(batch)) = reply
        .get("cursor")
        .and_then(Bson::as_document)
        .and_then(|c| c.get("firstBatch"))
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in batch {
        let Some(doc) = entry.as_document() else {
            continue;
        };
        let Ok(name) = doc.get_str("name") else {
            continue;
        };
        if name == "_id_" {
            continue;
        }
        let Some(key) = doc.get("key").and_then(Bson::as_document) else {
            continue;
        };
        let conditional =
            doc.contains_key("partialFilterExpression") || doc.get_bool("sparse").unwrap_or(false);
        out.push(SchemaIndex {
            name: name.to_string(),
            columns: key.keys().map(|k| KeyPart::Named(k.to_string())).collect(),
            unique: doc.get_bool("unique").unwrap_or(false) && !conditional,
        });
    }
    out
}

/// `$collStats: {count: {}}` -> the document count from the collection's
/// metadata. Not a scan, and not an estimate of anything about a QUERY.
pub fn count(batch: &[Document]) -> Option<u64> {
    let value = batch.first()?.get("count")?;
    match value {
        Bson::Int32(n) => u64::try_from(*n).ok(),
        Bson::Int64(n) => u64::try_from(*n).ok(),
        Bson::Double(n) if *n >= 0.0 => Some(*n as u64),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// nyet explain
// ---------------------------------------------------------------------------

/// The `queryPlanner` explain reply -> the plan nyet publishes.
///
/// **There is no cost and no row estimate here, and none is invented** (UX-7):
/// MongoDB's `queryPlanner` verbosity publishes neither, and the verbosities
/// that do (`executionStats`, `allPlansExecution`) RUN the query, which is the
/// one thing `explain` must never do. What the agent gets instead is what the
/// planner actually decided: the stages of the winning plan (a `COLLSCAN` says
/// "no index was usable" more plainly than any number), the index it chose,
/// the plans it rejected, and the winning plan verbatim — `indexBounds` and
/// all, because "why did my regex not use the index" is answered there and
/// nowhere else.
///
/// `documents` is the collection's own document count, named so it cannot be
/// read as an estimate of the query: it is a property of the COLLECTION, and it
/// is what turns "COLLSCAN" into "COLLSCAN over 40 million documents".
pub fn plan(reply: &Document, documents: Option<u64>) -> Value {
    let mut out = serde_json::Map::new();
    match find_query_planner(reply, 0) {
        Some(planner) => {
            if let Ok(ns) = planner.get_str("namespace") {
                out.insert("namespace".to_string(), Value::from(ns));
            }
            let winning = planner.get("winningPlan");
            let (stages, indexes) = summarize(winning);
            out.insert("stages".to_string(), Value::from(stages));
            if !indexes.is_empty() {
                out.insert("indexes".to_string(), Value::from(indexes));
            }
            let rejected: Vec<Value> = planner
                .get("rejectedPlans")
                .and_then(Bson::as_array)
                .map(|plans| {
                    plans
                        .iter()
                        .map(|p| {
                            let (stages, indexes) = summarize(Some(p));
                            let mut entry = serde_json::Map::new();
                            entry.insert("stages".to_string(), Value::from(stages));
                            if !indexes.is_empty() {
                                entry.insert("indexes".to_string(), Value::from(indexes));
                            }
                            Value::Object(entry)
                        })
                        .collect()
                })
                .unwrap_or_default();
            if !rejected.is_empty() {
                out.insert("rejected".to_string(), Value::Array(rejected));
            }
            if let Some(winning) = winning {
                out.insert(
                    "winning_plan".to_string(),
                    winning.clone().into_relaxed_extjson(),
                );
            }
        }
        // No `queryPlanner` anywhere in the reply: rather than answer with an
        // empty plan that reads like "nothing to do", hand over what the server
        // did say, minus the parts that are noise for an agent.
        None => {
            out.insert("explain".to_string(), stripped(reply));
        }
    }
    if let Some(documents) = documents {
        out.insert("collection_documents".to_string(), Value::from(documents));
    }
    Value::Object(out)
}

/// Keys of an explain reply that cost tokens and answer nothing: the server's
/// build info, its internal memory limits, and the echo of the agent's own
/// command (UX-4).
const EXPLAIN_NOISE: &[&str] = &[
    "$clusterTime",
    "command",
    "explainVersion",
    "ok",
    "operationTime",
    "queryShapeHash",
    "serverInfo",
    "serverParameters",
];

fn stripped(reply: &Document) -> Value {
    let mut kept = Document::new();
    for (key, value) in reply {
        if !EXPLAIN_NOISE.contains(&key.as_str()) {
            kept.insert(key.clone(), value.clone());
        }
    }
    Bson::Document(kept).into_relaxed_extjson()
}

/// The first `queryPlanner` in the reply. A `find` carries it at the top level;
/// an aggregation nests it inside `stages[0].$cursor` (measured on 8.2) — and a
/// future shape that nests it somewhere else is found by the same walk instead
/// of falling off a hard-coded path.
fn find_query_planner(doc: &Document, depth: usize) -> Option<&Document> {
    if depth > MAX_DEPTH {
        return None;
    }
    if let Some(planner) = doc.get("queryPlanner").and_then(Bson::as_document) {
        return Some(planner);
    }
    for (_, value) in doc {
        let found = match value {
            Bson::Document(sub) => find_query_planner(sub, depth + 1),
            Bson::Array(items) => items
                .iter()
                .filter_map(Bson::as_document)
                .find_map(|sub| find_query_planner(sub, depth + 1)),
            _ => None,
        };
        if found.is_some() {
            return found;
        }
    }
    None
}

/// A plan tree -> (stage names outermost first, index names). Generic on
/// purpose: MongoDB nests plan stages under `inputStage`, `inputStages`,
/// `queryPlan`, `thenStage`, `shards` and more depending on the query and the
/// execution engine, and a walk that collects every `stage`/`indexName` it
/// meets cannot miss one because a release renamed the link.
fn summarize(plan: Option<&Bson>) -> (Vec<String>, Vec<String>) {
    let mut stages = Vec::new();
    let mut indexes = Vec::new();
    if let Some(plan) = plan {
        collect(plan, 0, &mut stages, &mut indexes);
    }
    (stages, indexes)
}

fn collect(value: &Bson, depth: usize, stages: &mut Vec<String>, indexes: &mut Vec<String>) {
    if depth > MAX_DEPTH {
        return;
    }
    match value {
        Bson::Document(doc) => {
            if let Ok(stage) = doc.get_str("stage") {
                stages.push(stage.to_string());
            }
            if let Ok(index) = doc.get_str("indexName") {
                if !indexes.iter().any(|i| i == index) {
                    indexes.push(index.to_string());
                }
            }
            for (key, sub) in doc {
                // `filter`/`indexBounds`/`keyPattern` are the query's own
                // values, not plan structure — walking them would only spend
                // depth, and a user field called `stage` would land in the
                // answer as if the planner had said it.
                if matches!(key.as_str(), "filter" | "indexBounds" | "keyPattern") {
                    continue;
                }
                collect(sub, depth + 1, stages, indexes);
            }
        }
        Bson::Array(items) => {
            for item in items {
                collect(item, depth + 1, stages, indexes);
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// nyet doctor
// ---------------------------------------------------------------------------

/// Actions nyet knows to be READS. An allowlist, like everything else that
/// decides in this project: an action a future MongoDB adds is NOT quietly
/// counted as harmless, it lands in `Grants::unknown` and doctor says so.
/// Sorted — `binary_search`.
const READ_ACTIONS: &[&str] = &[
    "changeStream",
    "checkFreeMonitoringStatus",
    "collStats",
    "connPoolStats",
    "dbHash",
    "dbStats",
    "find",
    "getClusterParameter",
    "getCmdLineOpts",
    "getDatabaseVersion",
    "getDefaultRWConcern",
    "getLog",
    "getParameter",
    "getShardMap",
    "hostInfo",
    "indexStats",
    "inprog",
    "killCursors",
    "listCollections",
    "listDatabases",
    "listIndexes",
    "listSearchIndexes",
    "listSessions",
    "listShards",
    "performRawDataOperations",
    "planCacheRead",
    "replSetGetConfig",
    "replSetGetStatus",
    "serverStatus",
    "shardingState",
    "top",
    "useUUID",
    "viewRole",
    "viewUser",
];

/// Actions nyet knows to WRITE — data, indexes, users, or the cluster's own
/// state. Naming them buys a precise verdict ("insert on app.*") instead of the
/// vaguer "an action nyet cannot classify". Sorted.
const WRITE_ACTIONS: &[&str] = &[
    "anyAction",
    "applyOps",
    "bypassDocumentValidation",
    "cleanupStructuredEncryptionData",
    "collMod",
    "compact",
    "compactStructuredEncryptionData",
    "convertToCapped",
    "createCollection",
    "createIndex",
    "createRole",
    "createSearchIndexes",
    "createUser",
    "dropCollection",
    "dropConnections",
    "dropDatabase",
    "dropIndex",
    "dropRole",
    "dropSearchIndex",
    "dropUser",
    "emptycapped",
    "enableSharding",
    "flushRouterConfig",
    "fsync",
    "grantPrivilegesToRole",
    "grantRole",
    "insert",
    "internal",
    "killAnyCursor",
    "killAnySession",
    "killop",
    "reIndex",
    "refineCollectionShardKey",
    "remove",
    "renameCollectionSameDB",
    "repairDatabase",
    "revokePrivilegesFromRole",
    "revokeRole",
    "setParameter",
    "setUserWriteBlockMode",
    "shardCollection",
    "shutdown",
    "update",
    "updateRole",
    "updateSearchIndex",
    "updateUser",
];

/// Roles that hold administrative power over the database or the cluster: they
/// can grant themselves anything, so no layer below them holds. Sorted.
const SUPERUSER_ROLES: &[&str] = &[
    "__system",
    "backup",
    "clusterAdmin",
    "clusterManager",
    "dbAdminAnyDatabase",
    "dbOwner",
    "hostManager",
    "restore",
    "root",
    "userAdmin",
    "userAdminAnyDatabase",
];

/// How many resources the message names before it stops (the count is always
/// honest — see `Grants::write_count`), and how many actions it names per
/// resource. Bounds on the AGENT-facing text, not on the check (UX-4).
const MAX_LISTED: usize = 4;
const MAX_ACTIONS: usize = 4;

fn listed(list: &[&str], name: &str) -> bool {
    list.binary_search(&name).is_ok()
}

/// The write actions a human recognises at a glance, in the order they answer
/// "how much can this role break?". Everything else sorts after them (by name);
/// this is presentation only — the CHECK reads every action, and `write_count`
/// is the honest total.
const NOTABLE_WRITES: &[&str] = &[
    "anyAction",
    "dropDatabase",
    "remove",
    "insert",
    "update",
    "dropCollection",
    "createCollection",
    "createIndex",
    "dropIndex",
    "createUser",
    "grantRole",
    "shutdown",
];

fn rank(action: &str) -> usize {
    NOTABLE_WRITES
        .iter()
        .position(|a| *a == action)
        .unwrap_or(NOTABLE_WRITES.len())
}

/// `connectionStatus {showPrivileges: true}` -> what these credentials may do,
/// **on every resource of the cluster** and not only on the database nyet
/// reads: measured, a role that is `read` on one database and `readWrite` on
/// another can copy a collection out with `$out: {db: ..., coll: ...}`.
///
/// `None` = the server did not publish a privilege list at all (an older
/// server, a proxy that dropped the field). That is "could not verify", never a
/// pass — the caller turns it into a `warn`.
pub fn grants(auth_info: &Document, database: &str) -> Option<Grants> {
    let users = auth_info
        .get("authenticatedUsers")
        .and_then(Bson::as_array)
        .map_or(0, Vec::len);
    if users == 0 {
        return Some(Grants {
            writes: Vec::new(),
            write_count: 0,
            unknown: Vec::new(),
            unknown_count: 0,
            this_database: false,
            resources: 0,
            unauthenticated: true,
        });
    }
    let privileges = auth_info
        .get("authenticatedUserPrivileges")
        .and_then(Bson::as_array)?;
    let mut writes: Vec<String> = Vec::new();
    let mut write_count = 0;
    let mut unknown: Vec<String> = Vec::new();
    let mut unknown_count = 0;
    let mut this_database = false;
    for entry in privileges {
        let Some(privilege) = entry.as_document() else {
            continue;
        };
        let resource = privilege.get("resource").and_then(Bson::as_document);
        let (name, covers) = describe_resource(resource, database);
        let Some(actions) = privilege.get("actions").and_then(Bson::as_array) else {
            continue;
        };
        // Grouped BY RESOURCE, because that is the unit the human fixes: a
        // `readWrite` role lists two dozen write actions on one database, and
        // twenty-four lines of them say nothing the first three do not.
        let mut here: Vec<&str> = Vec::new();
        for action in actions.iter().filter_map(Bson::as_str) {
            if listed(READ_ACTIONS, action) {
                continue;
            }
            if listed(WRITE_ACTIONS, action) {
                here.push(action);
                continue;
            }
            let entry = format!("{action} on {name}");
            if unknown.contains(&entry) {
                continue;
            }
            unknown_count += 1;
            if unknown.len() < MAX_LISTED {
                unknown.push(entry);
            }
        }
        if here.is_empty() {
            continue;
        }
        write_count += 1;
        this_database |= covers;
        if writes.len() < MAX_LISTED {
            // The RECOGNISABLE writes first, then the rest alphabetically: cut
            // by name alone, a `readWrite` role reported
            // `cleanupStructuredEncryptionData, compactStructuredEncryptionData,
            // convertToCapped, createCollection, +10 more` and hid `insert`,
            // `update` and `remove` behind the "+10". The human reads this line
            // to judge how much wider than a read the role is.
            here.sort_by_key(|a| (rank(a), *a));
            let more = here.len().saturating_sub(MAX_ACTIONS);
            here.truncate(MAX_ACTIONS);
            writes.push(match more {
                0 => format!("{name} ({})", here.join(", ")),
                n => format!("{name} ({}, +{n} more)", here.join(", ")),
            });
        }
    }
    Some(Grants {
        writes,
        write_count,
        unknown,
        unknown_count,
        this_database,
        resources: privileges.len(),
        unauthenticated: false,
    })
}

/// A privilege resource -> (how to name it, does it cover the database this
/// connection reads). An unreadable resource is named as unknown and counted as
/// covering — fail closed.
fn describe_resource(resource: Option<&Document>, database: &str) -> (String, bool) {
    let Some(resource) = resource else {
        return ("an unnamed resource".to_string(), true);
    };
    if resource.get_bool("anyResource").unwrap_or(false) {
        return ("any resource".to_string(), true);
    }
    if resource.get_bool("cluster").unwrap_or(false) {
        return ("the cluster".to_string(), true);
    }
    let db = resource.get_str("db").unwrap_or("");
    let collection = resource.get_str("collection").unwrap_or("");
    let covers = db.is_empty() || db == database;
    let name = match (db.is_empty(), collection.is_empty()) {
        (true, true) => "every database".to_string(),
        (true, false) => format!("*.{collection}"),
        (false, true) => format!("{db}.*"),
        (false, false) => format!("{db}.{collection}"),
    };
    (name, covers)
}

/// Whether these credentials hold administrative power. Roles first (that is
/// what the human wrote), then the two actions that ARE administrative power
/// whatever role granted them.
pub fn superuser(auth_info: &Document) -> SuperuserFact {
    let Some(roles) = auth_info
        .get("authenticatedUserRoles")
        .and_then(Bson::as_array)
    else {
        return SuperuserFact::Unknown(
            "the server did not report the roles of these credentials".to_string(),
        );
    };
    if roles.is_empty() {
        return SuperuserFact::Unknown(
            "no user is authenticated on this connection, so there are no roles to judge"
                .to_string(),
        );
    }
    let mut names: Vec<String> = Vec::new();
    let mut admin: Vec<String> = Vec::new();
    for role in roles.iter().filter_map(Bson::as_document) {
        let Ok(name) = role.get_str("role") else {
            continue;
        };
        let db = role.get_str("db").unwrap_or("");
        let full = format!("{name}@{db}");
        if listed(SUPERUSER_ROLES, name) {
            admin.push(full.clone());
        }
        names.push(full);
    }
    if !admin.is_empty() {
        return SuperuserFact::Yes(format!(
            "these credentials hold the administrative role(s) {}",
            admin.join(", ")
        ));
    }
    SuperuserFact::No(format!("roles: {}", names.join(", ")))
}

/// `getCmdLineOpts` -> whether the server evaluates JavaScript.
///
/// MongoDB publishes NO runtime parameter for this (measured: `getParameter`
/// answers "no option found to get"), so the startup options are the only
/// honest source — and `--noscripting` sets `security.javascriptEnabled:
/// false`, while scripting being ON is simply the key's ABSENCE (measured on
/// 8.2.12, both ways). Reading argv as well means a server started with the
/// flag is recognised even if a future release stops normalising it.
pub fn javascript(reply: &Document) -> JsFact {
    let disabled_in_config = reply
        .get("parsed")
        .and_then(Bson::as_document)
        .and_then(|p| p.get("security"))
        .and_then(Bson::as_document)
        .and_then(|s| s.get_bool("javascriptEnabled").ok())
        == Some(false);
    let disabled_in_argv = reply
        .get("argv")
        .and_then(Bson::as_array)
        .is_some_and(|argv| {
            argv.iter()
                .filter_map(Bson::as_str)
                .any(|a| a == "--noscripting")
        });
    if disabled_in_config || disabled_in_argv {
        JsFact::Disabled
    } else {
        JsFact::Enabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mongodb::bson::doc;

    fn names(columns: &[SchemaColumn]) -> Vec<&str> {
        columns.iter().map(|c| c.name.as_str()).collect()
    }

    fn users_reply(batch: Vec<Bson>) -> Document {
        doc! { "cursor": { "id": 0_i64, "firstBatch": batch } }
    }

    #[test]
    fn collections_drops_internal_catalogs_and_reads_the_kind() {
        let reply = users_reply(vec![
            doc! { "name": "users", "type": "collection", "options": { "x": 1 } }.into(),
            doc! { "name": "active", "type": "view" }.into(),
            doc! { "name": "system.views", "type": "collection" }.into(),
            // Shapes a healthy server does not send: no name, not a document.
            doc! { "type": "collection" }.into(),
            Bson::Int32(7),
        ]);
        let got = collections(&reply).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].name, "active");
        assert_eq!(got[0].kind, "view");
        assert_eq!(got[1].kind, "collection");
        assert!(got[1].options.is_some());
    }

    #[test]
    fn a_partial_collection_list_is_an_error_not_a_short_answer() {
        let reply = doc! { "cursor": { "id": 42_i64, "firstBatch": [] } };
        assert!(collections(&reply).is_err());
        assert!(collections(&doc! { "ok": 1 }).is_err());
        assert!(collections(&doc! { "cursor": { "id": 0_i64 } }).is_err());
        // An empty database is an empty list, not an error.
        assert!(collections(&users_reply(vec![])).unwrap().is_empty());
    }

    #[test]
    fn sampled_fields_carry_their_provenance_and_how_often_they_were_seen() {
        let sample = vec![
            doc! { "_id": 1, "name": "a", "profile": { "city": "Berlin" }, "tags": ["x"] },
            doc! { "_id": 2, "name": "b" },
            doc! { "_id": 3, "name": Bson::Null, "rare": 1 },
        ];
        let table = table(
            "c".into(),
            "collection",
            None,
            &sample,
            Vec::new(),
            Some(99),
        );
        assert_eq!(table.count, Some(99));
        assert_eq!(table.sampled, Some(3));
        let columns = table.columns.unwrap();
        let by = |name: &str| {
            columns
                .iter()
                .find(|c| c.name == name)
                .unwrap_or_else(|| panic!("no {name} in {:?}", names(&columns)))
        };
        // Every one of them says it is a GUESS, and from how many documents.
        assert!(columns.iter().all(|c| c.source == Some("sample")));
        assert_eq!(by("rare").seen, Some(1));
        assert!(by("rare").nullable);
        // Seen in every document, but one of them held an explicit null.
        assert_eq!(by("name").seen, Some(3));
        assert_eq!(by("name").ty, "null|string");
        assert!(by("name").nullable);
        // _id is the one field MongoDB itself guarantees.
        assert!(by("_id").pk);
        assert!(!by("_id").nullable);
        // Nested paths are dotted, i.e. written the way a filter addresses them.
        assert_eq!(by("profile").ty, "object");
        assert_eq!(by("profile.city").ty, "string");
        assert_eq!(by("tags").ty, "array");
    }

    #[test]
    fn array_elements_are_counted_once_per_document() {
        let sample = vec![doc! { "items": [ { "sku": 1 }, { "sku": 2 }, { "sku": 3 } ] }];
        let columns = table("c".into(), "collection", None, &sample, Vec::new(), None)
            .columns
            .unwrap();
        let sku = columns.iter().find(|c| c.name == "items.sku").unwrap();
        assert_eq!(sku.seen, Some(1), "seen counts documents, not occurrences");
        assert!(!sku.nullable);
    }

    #[test]
    fn a_declared_validator_is_a_schema_and_says_so() {
        let options = doc! { "validator": { "$jsonSchema": {
            "bsonType": "object",
            "required": ["email"],
            "properties": {
                "email": { "bsonType": "string" },
                "age": { "bsonType": ["int", "null"] },
                "profile": { "bsonType": "object", "properties": { "city": { "bsonType": "string" } } },
                "untyped": { "description": "no type at all" },
            },
        }}};
        let sample = vec![doc! { "email": "a@b.c", "extra": 1 }, doc! { "extra": 2 }];
        let columns = table(
            "c".into(),
            "collection",
            Some(&options),
            &sample,
            Vec::new(),
            None,
        )
        .columns
        .unwrap();
        let by = |name: &str| columns.iter().find(|c| c.name == name).unwrap();
        assert_eq!(by("email").source, Some("validator"));
        assert_eq!(by("email").ty, "string");
        // Declared required, but only one of the two documents carries it: the
        // validator only ever applied to writes after it existed.
        assert_eq!(by("email").seen, Some(1));
        assert!(by("email").nullable);
        assert_eq!(by("age").ty, "int|null");
        assert!(by("age").nullable);
        assert_eq!(by("profile.city").source, Some("validator"));
        assert_eq!(by("untyped").ty, "any");
        // A field the validator does not mention is still shown — as a guess.
        assert_eq!(by("extra").source, Some("sample"));
        assert_eq!(by("extra").seen, Some(2));
    }

    #[test]
    fn a_query_expression_validator_is_not_a_schema() {
        let options = doc! { "validator": { "email": { "$exists": true } } };
        let columns = table(
            "c".into(),
            "collection",
            Some(&options),
            &[doc! { "email": "a" }],
            Vec::new(),
            None,
        )
        .columns
        .unwrap();
        assert_eq!(columns[0].source, Some("sample"));
    }

    #[test]
    fn the_field_list_is_capped_rarest_first() {
        // 150 distinct fields, each in one document; plus one in all of them.
        let sample: Vec<Document> = (0..150)
            .map(|n| doc! { "everywhere": 1, format!("f{n:03}"): n })
            .collect();
        let columns = table("c".into(), "collection", None, &sample, Vec::new(), None)
            .columns
            .unwrap();
        assert_eq!(columns.len(), MAX_FIELDS);
        assert!(columns.iter().any(|c| c.name == "everywhere"));
    }

    #[test]
    fn indexes_drop_the_id_index_and_do_not_promise_conditional_uniqueness() {
        let reply = users_reply(vec![
            doc! { "v": 2, "key": { "_id": 1 }, "name": "_id_" }.into(),
            doc! { "v": 2, "key": { "email": 1 }, "name": "email_1", "unique": true }.into(),
            doc! { "v": 2, "key": { "a": 1, "b": -1 }, "name": "a_1_b_-1" }.into(),
            doc! { "v": 2, "key": { "c": 1 }, "name": "c_1", "unique": true,
            "partialFilterExpression": { "c": { "$gt": 0 } } }
            .into(),
            doc! { "name": "no_key" }.into(),
        ]);
        let got = indexes(&reply);
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].name, "email_1");
        assert!(got[0].unique);
        assert_eq!(got[1].columns.len(), 2);
        assert!(!got[2].unique, "a partial unique index is not unique");
        // A reply with nothing in it is an empty list, never a panic.
        assert!(indexes(&doc! { "ok": 1 }).is_empty());
    }

    #[test]
    fn count_reads_every_integer_shape_and_refuses_the_rest() {
        assert_eq!(count(&[doc! { "count": 7_i32 }]), Some(7));
        assert_eq!(count(&[doc! { "count": 7_i64 }]), Some(7));
        assert_eq!(count(&[doc! { "count": 7.0 }]), Some(7));
        assert_eq!(count(&[doc! { "count": "7" }]), None);
        assert_eq!(count(&[doc! { "ns": "a.b" }]), None);
        assert_eq!(count(&[]), None);
    }

    #[test]
    fn a_find_plan_names_the_stages_the_index_and_the_rejected_plans() {
        let reply = doc! {
            "explainVersion": "1",
            "queryPlanner": {
                "namespace": "app.users",
                "winningPlan": {
                    "stage": "LIMIT",
                    "limitAmount": 11_i32,
                    "inputStage": {
                        "stage": "FETCH",
                        "inputStage": {
                            "stage": "IXSCAN",
                            "indexName": "email_1",
                            "keyPattern": { "email": 1 },
                            "indexBounds": { "email": ["[\"a\", \"a\"]"] },
                        },
                    },
                },
                "rejectedPlans": [ {
                    "stage": "FETCH",
                    "inputStage": { "stage": "IXSCAN", "indexName": "age_1" },
                } ],
            },
            "command": { "find": "users" },
            "serverInfo": { "version": "8.2.12" },
            "ok": 1.0,
        };
        let plan = plan(&reply, Some(51_234));
        assert_eq!(plan["namespace"], "app.users");
        assert_eq!(plan["stages"][0], "LIMIT");
        assert_eq!(plan["stages"][2], "IXSCAN");
        assert_eq!(plan["indexes"][0], "email_1");
        assert_eq!(plan["rejected"][0]["indexes"][0], "age_1");
        assert_eq!(plan["collection_documents"], 51_234);
        // The winning plan is passed through verbatim: indexBounds is where
        // "why did it not use my index" is actually answered.
        assert_eq!(
            plan["winning_plan"]["inputStage"]["inputStage"]["indexBounds"]["email"][0],
            "[\"a\", \"a\"]"
        );
        // The noise is gone (UX-4).
        assert!(plan.get("explain").is_none());
    }

    #[test]
    fn an_aggregation_plan_is_found_where_the_server_nests_it() {
        let reply = doc! {
            "stages": [
                { "$cursor": { "queryPlanner": {
                    "namespace": "app.users",
                    "winningPlan": { "stage": "COLLSCAN", "direction": "forward" },
                    "rejectedPlans": [],
                } } },
                { "$group": { "_id": Bson::Null } },
            ],
            "ok": 1.0,
        };
        let plan = plan(&reply, None);
        assert_eq!(plan["namespace"], "app.users");
        assert_eq!(plan["stages"][0], "COLLSCAN");
        assert!(plan.get("indexes").is_none());
        assert!(plan.get("rejected").is_none());
        assert!(plan.get("collection_documents").is_none());
    }

    #[test]
    fn a_plan_nyet_cannot_read_hands_over_what_the_server_said() {
        let reply = doc! { "stages": [ { "$listSomething": { } } ], "serverInfo": { "version": "9" }, "ok": 1.0 };
        let plan = plan(&reply, None);
        assert!(plan.get("stages").is_none());
        assert_eq!(
            plan["explain"]["stages"][0]["$listSomething"],
            serde_json::json!({})
        );
        assert!(plan["explain"].get("serverInfo").is_none());
        // Nothing at all is still an answer, not a panic.
        let _ = super::plan(&doc! {}, None);
    }

    #[test]
    fn a_user_field_called_stage_is_not_mistaken_for_the_planner_speaking() {
        let reply = doc! { "queryPlanner": {
            "namespace": "app.c",
            "winningPlan": { "stage": "COLLSCAN", "filter": { "stage": { "$eq": "shipped" } } },
        } };
        let plan = plan(&reply, None);
        assert_eq!(plan["stages"].as_array().unwrap().len(), 1);
    }

    fn auth(privileges: Vec<Bson>, roles: Vec<Bson>) -> Document {
        doc! {
            "authenticatedUsers": [ { "user": "app", "db": "app" } ],
            "authenticatedUserRoles": roles,
            "authenticatedUserPrivileges": privileges,
        }
    }

    #[test]
    fn the_read_role_is_read_only_and_says_so_without_writing_anything() {
        // The exact action list MongoDB 8.2 reports for role `read`.
        let actions = [
            "changeStream",
            "collStats",
            "dbHash",
            "dbStats",
            "find",
            "killCursors",
            "listCollections",
            "listIndexes",
            "listSearchIndexes",
            "planCacheRead",
            "performRawDataOperations",
        ];
        let privileges = vec![doc! {
            "resource": { "db": "app", "collection": "" },
            "actions": actions.iter().map(|a| Bson::from(*a)).collect::<Vec<_>>(),
        }
        .into()];
        let g = grants(
            &auth(
                privileges,
                vec![doc! { "role": "read", "db": "app" }.into()],
            ),
            "app",
        )
        .unwrap();
        assert_eq!(g.write_count, 0);
        assert!(g.unknown.is_empty());
        assert_eq!(g.resources, 1);
        assert!(!g.unauthenticated);
    }

    #[test]
    fn a_write_grant_anywhere_in_the_cluster_is_found_and_located() {
        let privileges = vec![
            doc! { "resource": { "db": "app", "collection": "" }, "actions": ["find"] }.into(),
            doc! { "resource": { "db": "scratch", "collection": "" },
            "actions": ["find", "insert", "update"] }
            .into(),
        ];
        let g = grants(&auth(privileges, vec![]), "app").unwrap();
        assert_eq!(g.write_count, 1, "one resource carries write actions");
        assert!(!g.this_database, "the writes are in another database");
        assert_eq!(g.writes[0], "scratch.* (insert, update)");

        // The listed actions are the RECOGNISABLE ones, not the alphabetically
        // first: cut by name, a `readWrite` role showed
        // `cleanupStructuredEncryptionData, compact…, convertToCapped,
        // createCollection` and hid `insert`/`update`/`remove` behind "+n more".
        let privileges = vec![
            doc! { "resource": { "db": "scratch", "collection": "" }, "actions": [
                "cleanupStructuredEncryptionData", "compactStructuredEncryptionData",
                "convertToCapped", "createCollection", "insert", "update", "remove", "find",
            ] }
            .into(),
        ];
        let g = grants(&auth(privileges, vec![]), "app").unwrap();
        assert_eq!(
            g.writes[0],
            "scratch.* (remove, insert, update, createCollection, +3 more)"
        );

        // The same actions on THIS database, and on resources that cover
        // everything, are the harder verdict.
        for resource in [
            doc! { "db": "app", "collection": "" },
            doc! { "db": "", "collection": "" },
            doc! { "cluster": true },
            doc! { "anyResource": true },
        ] {
            let privileges = vec![doc! { "resource": resource, "actions": ["insert"] }.into()];
            assert!(
                grants(&auth(privileges, vec![]), "app")
                    .unwrap()
                    .this_database
            );
        }
    }

    #[test]
    fn an_action_nyet_does_not_know_is_not_assumed_harmless() {
        let privileges = vec![doc! { "resource": { "db": "app", "collection": "" },
        "actions": ["find", "teleportDocuments"] }
        .into()];
        let g = grants(&auth(privileges, vec![]), "app").unwrap();
        assert_eq!(g.write_count, 0);
        assert_eq!(g.unknown, vec!["teleportDocuments on app.*"]);
        assert_eq!(g.unknown_count, 1);
    }

    #[test]
    fn a_reply_without_a_privilege_list_is_not_a_pass() {
        let mut auth = auth(vec![], vec![]);
        auth.remove("authenticatedUserPrivileges");
        assert!(grants(&auth, "app").is_none());
        // No user at all: there is no role that could be read-only.
        let none = doc! { "authenticatedUsers": [], "authenticatedUserPrivileges": [] };
        assert!(grants(&none, "app").unwrap().unauthenticated);
    }

    #[test]
    fn superuser_reads_the_roles_and_admits_when_it_cannot() {
        assert!(matches!(
            superuser(&auth(
                vec![],
                vec![doc! { "role": "read", "db": "app" }.into()]
            )),
            SuperuserFact::No(_)
        ));
        assert!(matches!(
            superuser(&auth(
                vec![],
                vec![
                    doc! { "role": "read", "db": "app" }.into(),
                    doc! { "role": "root", "db": "admin" }.into(),
                ]
            )),
            SuperuserFact::Yes(_)
        ));
        assert!(matches!(
            superuser(&auth(vec![], vec![])),
            SuperuserFact::Unknown(_)
        ));
        assert!(matches!(
            superuser(&doc! { "ok": 1 }),
            SuperuserFact::Unknown(_)
        ));
    }

    #[test]
    fn scripting_is_read_from_the_startup_options_both_ways() {
        // Measured on 8.2.12: --noscripting sets the parsed key to false, and
        // scripting being ON is the key's ABSENCE.
        assert!(matches!(
            javascript(&doc! { "argv": ["mongod", "--noscripting", "--auth"],
            "parsed": { "security": { "javascriptEnabled": false, "authorization": "enabled" } } }),
            JsFact::Disabled
        ));
        assert!(matches!(
            javascript(&doc! { "argv": ["mongod", "--auth"],
            "parsed": { "security": { "authorization": "enabled" } } }),
            JsFact::Enabled
        ));
        // Only argv carries it (a future release that stops normalising it).
        assert!(matches!(
            javascript(&doc! { "argv": ["mongod", "--noscripting"] }),
            JsFact::Disabled
        ));
        assert!(matches!(javascript(&doc! { "ok": 1 }), JsFact::Enabled));
    }

    #[test]
    fn action_lists_are_sorted_and_disjoint() {
        for (name, list) in [
            ("READ_ACTIONS", READ_ACTIONS),
            ("WRITE_ACTIONS", WRITE_ACTIONS),
            ("SUPERUSER_ROLES", SUPERUSER_ROLES),
        ] {
            let mut sorted = list.to_vec();
            sorted.sort_unstable();
            assert_eq!(list, sorted.as_slice(), "{name} must stay sorted");
            sorted.dedup();
            assert_eq!(list.len(), sorted.len(), "{name} has a duplicate");
        }
        for action in READ_ACTIONS {
            assert!(
                !listed(WRITE_ACTIONS, action),
                "{action} cannot be both a read and a write"
            );
        }
    }
}
