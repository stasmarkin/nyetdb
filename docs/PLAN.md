# nyetdb — План имплементации

ROADMAP отвечает «что и зачем», этот план — «в каком порядке». Правила
нарезки шагов:

- **Каждый шаг добавляет бизнес-value** — после мержа пользователь (человек
  или агент) умеет что-то новое, что можно показать.
- **Каждый шаг self-contained** — без заделов «на будущее»: код, который
  понадобится в шаге N+2, пишется в шаге N+2 (YAGNI пошагово, Д5).
- **Definition of Done для каждого шага:**
  1. тесты написаны и зелёные (корпус/интеграционные/snapshot — по природе шага);
  2. README.md (инструкция по эксплуатации) дописан под новую возможность;
  3. docs/DEV.md (инструкция по разработке) дописан, если менялась структура
     или процесс;
  4. fmt + clippy (deny warnings) + cargo-deny чистые;
  5. один шаг = один PR/коммит в main с внятным сообщением.

Порядок движков — прагматичный и отличается от продуктового приоритета
ROADMAP: SQLite идёт первым как walking skeleton (весь пайплайн без серверов
и testcontainers), PostgreSQL остаётся флагманом релиза. Релиз v0.1
объявляется после шага 6.

---

## Шаг 1 — Скелет: конфиг + резолвер + `nyet list` + CI

**Value:** человек пишет конфиг и сразу проверяет его валидность и scoping;
агент видит, какие подключения доступны из текущей папки.

**Скоуп:**
- clap-скелет (`list`, `query` как заглушка с честной ошибкой `NOT_IMPLEMENTED`);
- config: toml → чистые структуры, env-подстановка `${VAR}`, `password_env`,
  unknown key = ошибка, warning про права файла;
- resolver: (cwd, config) → доступные подключения (canonicalize, префикс);
- JSON-конверт v1 (`ok`/`error`), exit-коды 0/1/2/3/4;
- GitHub Actions CI: fmt, clippy (deny), test, cargo-deny + cargo-audit.

**Тесты:** unit на config (валидный/битый/env/права), unit на resolver
(символические ссылки, `~`, вложенные пути), snapshot конверта `list`.

**Доки:** README: установка, полный пример конфига, `nyet list`.
Создаётся docs/DEV.md: сборка, запуск тестов, карта модулей (из PRINCIPLES Д2).

## Шаг 2 — `nyet query` для SQLite: первый end-to-end

**Value:** агент безопасно читает локальные `.db`-файлы — уже полезно в
реальной работе (у агентов постоянно под рукой SQLite).

**Скоуп:**
- trait `Engine` + SQLite-движок (sqlx, `mode=ro` — file-level read-only);
- валидатор, минимальное ядро: parse (fail-closed) → single statement →
  top-level allowlist (`Query`/`Explain`/`Show*`/`Describe`);
- row limit (fetch limit+1 → `truncated`), timeout;
- вывод: json (default) + table; поле `warnings`; exit-коды 5/7/8.

**Тесты:** первый golden-корпус (`tests/corpus/*.yaml`, SQLite-диалект:
allow/deny базовые), интеграционные на fixture-базе, snapshot конверта
успеха/отказа/обрезки.

**Доки:** README: `nyet query`, форматы, как читать отказ (`NYET` + reason +
hint). DEV: как устроен корпус и как добавить кейс.

## Шаг 3 — Валидатор целиком (слой 1 как заявлено в DESIGN)

**Value:** модель безопасности слоя 1 полностью соответствует DESIGN §3 —
для всех текущих и будущих SQL-движков; появляется настраиваемость policy.

**Скоуп:**
- нормализация Unicode (Cf/Cc) + warning `UNICODE_STRIPPED`;
- рекурсивный AST-visitor: writes в CTE/подзапросах;
- locking clauses (`FOR UPDATE`/`FOR SHARE`);
- denylist функций per-engine + `validator.allow_functions`/`deny_functions`
  из конфига;
- форматы вывода jsonl (конверт в stderr) и csv.

**Тесты:** корпус пополняется всеми известными обходами (CTE-write,
multi-statement, SET, zero-width, denylist, locking) — это и есть публичная
спецификация безопасности; unit на merge policy из конфига.

**Доки:** README: секция Security — что блокируется, что настраивается.
DEV: процесс «нашёл обход → падающий тест в корпус → фикс».

## Шаг 4 — PostgreSQL: флагманский движок

**Value:** главный сценарий продукта — агент читает прод/стейдж PostgreSQL.

**Скоуп:**
- Postgres-движок: `default_transaction_read_only=on` + обёртка
  `SET TRANSACTION READ ONLY` + `statement_timeout` (слой 2);
- PostgreSqlDialect в валидаторе, Pg-ветка корпуса.

**Тесты:** testcontainers: слой 2 реально держит (write, протащенный мимо
валидатора руками, падает на уровне БД); e2e query/timeout/row-limit.

**Доки:** README: подключение Postgres, рекомендация read-only роли (с SQL
для её создания). DEV: как гонять интеграционные тесты локально (docker).

## Шаг 5 — SSH-туннели

**Value:** прод за бастионом — самый частый реальный сетап — работает.

**Скоуп:** шелл-аут в системный `ssh -N -L` с `ControlMaster=auto
ControlPersist=15m`, случайный локальный порт, ошибки туннеля → exit 6 с
внятным hint.

**Тесты:** интеграционный с openssh-контейнером (touch-стенд:
контейнер-бастион + контейнер-Postgres); unit на построение командной строки
ssh и разбор ошибок.

**Доки:** README: секция ssh-конфига с примером. DEV: как поднять ssh-стенд.

## Шаг 6 — MySQL/MariaDB + релизный пайплайн → **релиз v0.1**

**Value:** вторая серверная база; тула ставится одной командой без cargo.

**Скоуп:**
- MySQL-движок (`SET SESSION TRANSACTION READ ONLY`, `max_execution_time`),
  MySqlDialect-ветка корпуса, testcontainers;
- dist: GitHub Releases + shell installer + Homebrew tap; версия 0.1.0;
- README: safety-история как главный питч (материал для анонса).

**Доки:** README: установка через installer/brew. DEV: release process
(тег → dist → артефакты).

---

## После v0.1 (нарезка уточнится по обратной связи)

Каждый пункт — такой же self-contained шаг со своим value/тестами/доками:

7. `nyet schema` — introspection, токен-оптимизированный формат (UX-3, UX-4).
8. `nyet explain` + auto-guardrail по стоимости плана.
9. `nyet doctor` — честная диагностика сетапа (UX-7).
10. `nyet agent-setup` — генерация инструкции для AGENTS.md/скилла (UX-3).
11. Аудит-лог (UX-8).
12. npm-обёртка через dist (закрывает бэклог npm-имён).
13. Redis-движок (`COMMAND INFO`).
14. MongoDB-движок (свой allowlist команд).
15. ClickHouse-движок (`readonly=1`).
16. Connection daemon — только после замеров латентности (ROADMAP v0.5).

## Правила ведения плана

- План — живой: после каждого шага сверяемся, следующий шаг можно перерезать.
- Шаг не начинается, пока предыдущий не задеплоен в main с зелёным CI.
- Если посреди шага обнаружился «нужный задел на будущее» — это сигнал
  перерезать шаги, а не написать задел (Д5).
