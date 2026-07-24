# nyetdb

> **Your AI agent can look. For everything else — nyet.**

`nyet` is a safety-first CLI for read-only database access by AI agents
(Claude Code, Cursor, and other harnesses). One user-owned config file with
credentials, per-directory scoping, layered read-only enforcement (SQL AST
validation + session-level read-only + read-only roles), and JSON output
designed for agents — including structured warnings about heavy queries and
missing indexes.

Planned support: PostgreSQL, MySQL/MariaDB, SQLite, Redis, MongoDB, ClickHouse.

## Status

**Design phase.** The name is reserved; the tool is under active development.

- [Roadmap](ROADMAP.md)
- [Design](docs/DESIGN.md)

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
