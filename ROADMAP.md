# nyetdb — Roadmap

CLI-утилита на Rust для доступа к базам данных, ориентированная на AI-агентов
(Claude Code, Cursor и т.п.) и harness'ы.

> **Your AI agent can look. For everything else — nyet.**

**Имя:** бренд/репозиторий/крейт — `nyetdb`, бинарник — `nyet` (паттерн
ripgrep→`rg`: бренд уникален и гуглится, команда короткая). Крейт `nyet` и
npm-пакет `nyet` застолблены как алиасы. Проверено (июль 2026): crates.io,
npm, Homebrew, GitHub свободны для обоих имён.

**Позиционирование:** safety-first CLI. Дифференциация — не широта поддержки баз
(там Google MCP Toolbox с ~47 источниками), а связка **plain CLI + layered
read-only + directory scoping + agent UX** (структурированные подсказки, schema
introspection, auto-guardrail через EXPLAIN). Ниша подтверждена исследованием
(июль 2026): universal CLI (usql) не имеют валидации запросов, AI-конкуренты
(MCP Toolbox, DBHub) пошли по пути MCP-серверов; бенчмарки показывают, что CLI
для агентов дешевле по токенам и не хуже по success rate. Пространство имён и
ниша «сдержи AI-агента» активно разбираются (nono, leash, declaw — все 2025–26).

## Принципы

- **CLI-first, MCP later.** MCP-режим — обёртка из того же бинарника, не наоборот.
- **Layered security, не один слой.** AST-валидация (sqlparser-rs, fail-closed) +
  сессионный read-only (`default_transaction_read_only=on`, `SET TRANSACTION READ
  ONLY`, single-statement) + рекомендация read-only роли/реплики (`nyet doctor`).
  Наивный allowlist по `Statement::Query` недостаточен (writes внутри CTE и т.п.).
- **Конфиг создаёт только пользователь.** Креденшалы не попадают в контекст LLM —
  агент оперирует алиасами.
- **Directory scoping — UX-барьер, не security boundary** (cwd спуфится агентом).
  Честно документируем; настоящая граница — слои read-only.
- **nyet разговаривает с агентом**: поле `warnings` в ответе (обрезка, тайминги,
  отсутствие индексов), а не просто данные. Отказ — это фича и бренд: код `NYET`.

## Стек

| Область | Выбор |
|---|---|
| PostgreSQL / MySQL / MariaDB / SQLite | sqlx (динамический `query()`, MSSQL не поддерживается) |
| Redis / Valkey | redis-rs (`tokio-comp`, низкоуровневый `cmd()`; классификация write-команд — родной `COMMAND INFO`) |
| MongoDB | официальный крейт `mongodb` (своя read/write-классификация команд) |
| Cassandra / ScyllaDB | крейт `scylla` (отложено, по спросу) |
| SQL-валидация | sqlparser (apache/datafusion-sqlparser-rs), фича `visitor` |
| CLI / конфиг / вывод | clap, serde + toml (+ env-подстановка `${VAR}`), serde_json |
| Runtime | tokio |
| Композиция драйверов | cargo feature flags; релизный бинарник — со всеми |
| SSH-туннели | шелл-аут в системный `ssh` (наследует ~/.ssh/config, agent, ProxyJump); russh — только по жалобам |
| Дистрибуция | dist (форк astral-sh/cargo-dist): GitHub Releases, shell installer, Homebrew, npm-обёртка. Крейт `nyetdb`, `[[bin]] name = "nyet"` |

## Приоритет баз

1. **PostgreSQL** — MVP, эталонный вертикальный срез.
2. **MySQL/MariaDB, SQLite** — почти бесплатно поверх sqlx; SQLite = демо и локальные `.db` агентов.
3. **Redis** — дешёвая реализация, частый сценарий «посмотри что в кэше».
4. **MongoDB** — большая аудитория, дороже из-за своей классификации команд.
5. **ClickHouse** — вместо Cassandra в приоритете: популярен у девелоперов,
   analytics-запросы от агентов, родной `readonly=1`, диалект есть в sqlparser-rs.
6. Cassandra/ScyllaDB, MSSQL (tiberius), Elasticsearch, DWH — по запросам пользователей.

## Вехи

### v0.1 — вертикальный срез (PostgreSQL end-to-end)

- [ ] Скелет: clap, конфиг toml + env-подстановка, проверка прав файла (warn если не 0600)
- [ ] Резолвер: алиас + cwd → connection (`allowed_dirs`)
- [ ] Trait `Engine`; реализация PostgreSQL (sqlx)
- [ ] Валидатор: sqlparser-rs — fail-closed, single-statement, запрет
      transaction-control/SET, рекурсивный обход AST (writes в CTE/подзапросах)
- [ ] Сессионный read-only + statement timeout + row limit (default 30s / 1000
      строк, per-connection override; `"truncated": true` при обрезке)
- [ ] SSH-туннели: системный ssh, `ControlMaster=auto ControlPersist=15m` по
      умолчанию → переиспользование туннеля между запусками бесплатно
- [ ] Форматтеры: json (default) / jsonl / table / csv; токен-экономный JSON
- [ ] `nyet list` — доступные подключения из cwd
- [ ] Поле `warnings` в ответе
- [ ] Прогон валидатора на корпусе реальных запросов (замерить долю ложных
      fail-closed отказов до фиксации поведения)

### v0.2 — ширина sqlx + релиз

- [ ] MySQL/MariaDB, SQLite (переиспользуют пайплайн)
- [ ] dist: релизный пайплайн, инсталлеры, Homebrew tap, npm-пакет
- [ ] README: safety-история + бенчмарк токенов vs MCP-серверы (материал для HN)

### v0.3 — agent UX (ключевые дифференциаторы)

- [ ] `nyet schema <alias> [table]` — компактный introspection (таблицы,
      колонки, индексы, FK), токен-оптимизированный формат
- [ ] `nyet explain` — EXPLAIN с человекочитаемым вердиктом
- [ ] Auto-guardrail: EXPLAIN перед тяжёлым запросом; стоимость выше порога →
      не выполнять, вернуть план и совет
- [ ] `nyet doctor` — коннективность, реально ли read-only роль (write в
      откатываемой транзакции), не superuser ли, права конфига
- [ ] `nyet agent-setup` — сниппет для AGENTS.md / скилл с примерами
- [ ] Аудит-лог `~/.local/share/nyet/audit.jsonl`

### v0.4 — NoSQL

- [ ] Redis (COMMAND INFO как классификатор write-команд)
- [ ] MongoDB (своя классификация команд)
- [ ] ClickHouse (`readonly=1`)

### v0.5 — экосистема

- [ ] Connection daemon: фоновый пул живых DB-соединений (unix socket 0600,
      idle-kill 15м, автоспавн/автовыход, паттерн gpg-agent). Триггер — замеры
      латентности после MVP (ControlPersist уже снял стоимость туннеля; демон
      нужен, если 50–300 мс TLS/auth всё ещё мешают или из-за topology discovery
      MongoDB)
- [ ] `nyet mcp` — MCP-режим из того же бинарника
- [ ] `nyet sample <alias> <table>` — сэмплирование данных
- [ ] PII-маскирование (per-connection колонки/regex)
- [ ] Writes с opt-in: `allow_writes = true` в конфиге + `--unsafe-allow-writes`
- [ ] Кэш схемы

### Сознательно вне скоупа

Дампы/бэкапы (write-территория, огромный скоуп), интерактивный REPL (есть
pgcli), курсорная пагинация (LIMIT + warning покрывают 95%).

## Известные риски и открытые вопросы

- sqlparser-rs — syntax-only: доля легитимных запросов, отбиваемых fail-closed,
  неизвестна до прогона на реальном корпусе (веха v0.1).
- `default_transaction_read_only` — сессионная настройка, теоретически
  откатывается через SET; компенсируется запретом SET/multi-statement на слое
  валидатора и рекомендацией read-only роли.
- Prompt injection через результаты запросов — полной защиты не существует;
  митигации: read-only scoping, аудит-лог, предупреждение в доках.
- Готовой поддерживаемой классификации write-команд для MongoDB/CQL нет —
  ведём свою (Redis закрыт через COMMAND INFO).
- Хранение креденшалов: MVP — файл 0600 + env-подстановка; OS keychain — по
  спросу.
- Имя `nyet` — обычное слово: SEO зарабатывается контентом и брендом `nyetdb`;
  холодновойный флёр — осознанное решение (панк-брендинг, самоирония автора).
