# nyetdb — Design (draft)

> **Your AI agent can look. For everything else — nyet.**

Бренд/крейт — `nyetdb`, бинарник — `nyet`. Статус: решения согласованы
(июль 2026), можно начинать v0.1.

---

## 1. CLI-контракт

Контракт stdout/stderr/exit-codes — публичный API для агентов. Меняется только
через bump поля `v` в ответе.

### Команды

```
nyet query <alias> <query> [--format json|jsonl|table|csv] [--limit N] [--timeout SECS]
nyet list [--format json|table]
nyet schema <alias> [table] [--format json|table]
nyet explain <alias> <query> [--format json|table]
nyet doctor [alias] [--format json|table]
nyet agent-setup                   # v0.3
```

### Потоки

- **stdout** — всегда ровно один JSON-конверт (успех или ошибка). Агент читает
  один поток и парсит один формат.
- **stderr** — только человекочитаемая диагностика/логи (`-v`). Агенту парсить
  не нужно.
- Исключение — форматы `table`/`csv`/`jsonl`: данные в stdout в своём формате,
  конверт без `rows` — одной JSON-строкой в stderr. Место конверта определяется
  форматом, а не исходом: для этих форматов и ошибочный конверт идёт в stderr,
  а stdout при ошибке остаётся пустым (в stdout — только данные, никогда конверт).

### JSON-конверт

Успех:

```json
{
  "v": 1,
  "ok": true,
  "rows": [ {"id": 1, "email": "a@b.c"}, ... ],
  "meta": { "row_count": 2, "truncated": false, "duration_ms": 42, "connection": "prod" },
  "warnings": [ {"code": "SLOW_QUERY", "message": "query took 12.3s"} ]
}
```

Отказ валидатора **или guardrail'а** — фирменный код `NYET`, конкретика в
`reason` (валидаторные reason'ы + `EXPENSIVE_QUERY`, владелец которого —
guardrail; отказ guardrail'а дополнительно несёт top-level поле `estimate` с
планом и оценкой):

```json
{
  "v": 1,
  "ok": false,
  "error": {
    "code": "NYET",
    "reason": "WRITE_OPERATION",
    "message": "nyet: write operation DELETE found inside WITH clause",
    "hint": "nyet is read-only; rewrite the query without data modification"
  }
}
```

Прочие ошибки (конфиг, соединение, timeout, ошибка БД) — обычные коды
(`CONFIG_INVALID`, `CONNECTION_FAILED`, `TIMEOUT`, `DB_ERROR`, ...) без
`reason`.

Правила стабильности: поля только добавляются; переименование/удаление/смена
типа = breaking change = bump `v`. `warnings[].code`, `error.code` и
`error.reason` — часть контракта (закрытые перечни, документируются).

### Exit-коды

| Код | Значение |
|---|---|
| 0 | успех (в т.ч. с warnings) |
| 1 | внутренняя ошибка nyet |
| 2 | ошибка использования CLI (clap default) |
| 3 | ошибка конфига (не найден, невалиден, битые права) |
| 4 | подключение недоступно из текущей папки (directory scoping) |
| 5 | запрос отклонён валидатором или guardrail'ом (`error.code = "NYET"`) |
| 6 | ошибка соединения/auth (сеть, ssh-туннель, креденшалы) |
| 7 | база вернула ошибку выполнения |
| 8 | timeout |

Агент различает классы ошибок по exit-коду без парсинга текста; детали — в
`error.reason`/`error.message`.

---

## 2. Конфигурация

### Поиск файла

`--config <path>` → `$NYET_CONFIG` → `~/.config/nyet/config.toml`. Всё.

**Проектного конфига (`.nyet.toml` в репозитории) сознательно нет** — файл в
репозитории может быть создан агентом или подъехать через PR, что ломает
инвариант «конфиг создаёт только пользователь».

### Схема

```toml
# Глобальные дефолты (переопределяются per-connection)
[defaults]
row_limit = 1000
timeout_secs = 30
format = "json"
max_row_limit = 10000                  # опциональные потолки: выше них
max_timeout_secs = 60                  # --limit/--timeout агента не поднимут

[connections.prod]
engine = "postgres"                    # postgres | mysql | sqlite (v0.2) | ...
url = "postgres://nyet_ro@db.internal:5432/app"
password_env = "PROD_DB_PASSWORD"      # имя env-переменной; в конфиге пароля нет
allowed_dirs = ["~/Workspace/app"]     # пусто/отсутствует = запрещено везде
row_limit = 500
timeout_secs = 10
max_row_limit = 5000                   # потолки per-connection перекрывают
max_timeout_secs = 30                  # [defaults]

[connections.prod.validator]
allow_functions = ["pg_sleep"]         # убрать из встроенного denylist (осознанный риск)
deny_functions  = ["my_scary_fn"]      # добавить свои запреты
# для Redis/Mongo (v0.4) — та же пара: allow_commands / deny_commands

[connections.prod.guardrail]
mode = "cost"                          # cost | rows | off; дефолт зависит от движка
max_cost = 1000000.0                   # порог для mode = "cost" (только PostgreSQL)
max_rows = 10000000                    # порог для mode = "rows"

[connections.prod.ssh]
host = "deploy@bastion.corp:22"
remote = "db.internal:5432"            # куда пробрасывать с бастиона
control_persist = "15m"                # ControlMaster=auto ControlPersist

[connections.localdev]
engine = "sqlite"
path = "./dev.db"                      # sqlite: path вместо url, mode=ro
allowed_dirs = ["~/Workspace/app"]
```

### Правила

- **Секреты**: приоритетный способ — `password_env`; также подстановка
  `${VAR}` в любых строковых значениях. Отсутствующая переменная — жёсткая
  ошибка (exit 3), не пустая строка.
- **Права файла**: если у конфига есть group/other-биты — warning в stderr при
  каждом запуске + пункт в `doctor`. Не отказ — чтобы не ломать нестандартные
  сетапы (CI, контейнеры).
- **`allowed_dirs`**: сравнение канонизированных путей (realpath, симлинки
  разрешаются, `~` раскрывается) по префиксу. Глобов в v0.1 нет. cwd берётся
  из процесса; это UX-барьер, не security boundary (см. threat model).
  Пустой или отсутствующий `allowed_dirs` = запрещено везде (fail closed);
  «доступно отовсюду» задаётся явно: `allowed_dirs = ["~"]`. Записи — только
  статические литералы: подстановка `${VAR}` в `allowed_dirs` запрещена
  (env контролирует вызывающий агент — он мог бы расширить scope), как и
  относительные пути, `..`-компоненты и rooted-остаток после `~/` (`~//...`).
- **`validator.allow_functions` / `deny_functions`**: правят встроенный
  denylist per-connection. Policy настраивается; внутренняя механика
  (как получается классификация) — нет.
- **Потолки `max_row_limit` / `max_timeout_secs`**: effective = min(обычный
  резолв flag→conn→defaults→встроенный, потолок). Потолок клампит и флаг, и
  конфигурное значение выше него (противоречие в конфиге — в строгую сторону),
  кламп молчаливый. Ключей нет → поведение прежнее. Потолок `0` — ошибка (exit 3).
- **Policy-значения — только литералы**: подстановка `${VAR}` запрещена в
  `allowed_dirs`, `validator.allow_functions`/`deny_functions` и
  `guardrail.mode`. Окружением управляет вызывающий агент (threat model), а
  через эти ключи он иначе расширил бы себе scope, снял бы запрет функции или
  выключил guardrail.
- **`guardrail`**: режим, не поддерживаемый движком (`cost` для MySQL/SQLite,
  любой кроме `off` для SQLite), неизвестный `mode`, порог `<= 0` и порог,
  который активный режим не читает (`max_rows` при `mode = "cost"`), — жёсткая
  ошибка (exit 3), а не тихий откат к «без guardrail». Глобальных дефолтов в
  `[defaults]` для guardrail нет (YAGNI): порог — свойство конкретной базы.
- Неизвестные ключи в конфиге — жёсткая ошибка (fail loud, ловит опечатки).

---

## 3. Валидатор (SQL-движки)

Слой 1 из трёх (слой 2 — сессионный read-only, слой 3 — read-only роль,
рекомендуемая через `doctor`). Принцип: **fail closed** — всё, что валидатор
не понял, отклоняется. Любой deny → `error.code = "NYET"` + `reason` из
перечня ниже.

### Пайплайн

1. **Нормализация.** Удалить символы Unicode-категорий Cf/Cc (кроме \t \n \r)
   — защита от zero-width-инъекций в ключевые слова. Если такие символы были —
   warning `UNICODE_STRIPPED`.
2. **Парсинг** sqlparser-rs с диалектом движка (`PostgreSqlDialect`,
   `MySqlDialect`, `SQLiteDialect`). Не распарсилось → deny `PARSE_FAILED`.
3. **Ровно один statement.** Иначе deny `MULTI_STATEMENT`.
4. **Allowlist верхнего уровня:** `Query`, `Explain`, `ExplainTable`, `Show*`,
   `Describe`. Всё остальное (включая `Set*`, `StartTransaction`, `Commit`,
   `Rollback`, любой DDL/DML) → deny `WRITE_OPERATION` / `TXN_CONTROL`.
5. **Рекурсивный обход AST** (фича `visitor`): deny, если внутри найдены
   Insert/Update/Delete/Merge/Copy/DDL — ловит writes в CTE
   (`WITH x AS (DELETE ...) SELECT ...`) и подзапросах.
6. **Locking clauses:** `SELECT ... FOR UPDATE / FOR SHARE` → deny
   `LOCKING_CLAUSE` (слой 2 их тоже отобьёт, но здесь ошибка понятнее).
7. **Denylist функций** (расширяемый, per-engine): административные и опасные
   функции, которые работают даже в read-only транзакции — для PostgreSQL:
   `pg_terminate_backend`, `pg_cancel_backend`, `pg_reload_conf`, `pg_promote`,
   `pg_sleep`, `pg_read_file`, `lo_import`, `dblink*` → deny `DENIED_FUNCTION`.
   Список стартовый и пополняется. `pg_sleep` — deny (тихий DoS через занятие
   пула соединений; агенту незачем, легитимный кейс редкий и ручной).
   Переопределяется в конфиге: `validator.allow_functions` / `deny_functions`.

Вердикт: `Allow { warnings } | Deny { reason, message, hint }`.

### Слой 2 — сессионный read-only (per-engine)

| Движок | Механизм |
|---|---|
| PostgreSQL | `options=-c default_transaction_read_only=on -c statement_timeout=<ms>`; запрос в явной транзакции с `SET TRANSACTION READ ONLY` |
| MySQL/MariaDB | `SET SESSION TRANSACTION READ ONLY`; `max_execution_time` |
| SQLite | открытие файла в режиме `mode=ro` (file-level, сильнее сессионного) |

Row limit — клиентский: fetch `limit + 1` строк; если пришло больше limit —
`truncated: true` и warning.

### Golden-корпус

`tests/corpus/*.yaml`: запрос + движок + ожидаемый вердикт (+ reason). Обязаны
быть покрыты: все известные обходы (CTE-writes, multi-statement, SET, locking,
zero-width unicode, denylist-функции), а также представительный набор
легитимных сложных SELECT'ов (замер доли ложных отказов — веха v0.1).

### Не-SQL движки (v0.4, эскиз)

- Redis: классификация по флагам из `COMMAND INFO` (write/readonly) — allowlist
  генерируется из самой базы. Без кэша: запрашивается при коннекте (один
  дешёвый roundtrip, всегда соответствует версии сервера); кэш станет
  естественным свойством connection daemon (v0.5), если тот появится.
  Переопределение policy — `validator.allow_commands` / `deny_commands`.
- MongoDB: собственный allowlist read-команд (find, aggregate без `$out`/`$merge`,
  count, distinct, listCollections, ...). Aggregate-пайплайны сканируются на
  пишущие стадии.

---

## 4. Threat model

### Активы

Целостность данных prod-баз; доступность (тяжёлые запросы); конфиденциальность
креденшалов.

### В скоупе (от чего защищаем)

- **Кооперативный, но ошибающийся агент**: случайный UPDATE/DELETE/DDL,
  «удружил и почистил таблицу», writes, индуцированные prompt injection из
  данных/тикетов/PR.
- **Тяжёлые запросы**: full scan на десятки миллионов строк, отсутствие LIMIT —
  митигируются timeout, row limit и auto-guardrail через EXPLAIN (оценка плана
  выше порога → запрос не выполняется, `NYET`/`EXPENSIVE_QUERY`, exit 5).
  Guardrail — best effort против монстров, а не гарантия: движок без оценок
  (SQLite) и нераспарсенный план его не включают (см. docs/DEV.md).
- **Попадание креденшалов в контекст LLM**: агент оперирует алиасами; пароли —
  только в env/конфиге, nyet никогда не выводит их в stdout/stderr/логи.

### Вне скоупа (от чего НЕ защищаем — говорим честно)

- **Агент с shell-доступом, обходящий nyet**: он может прочитать конфиг и
  пойти в базу напрямую (psql/nc). Митигация — не nyet, а слой 3: read-only
  роль БД, тогда и прямой доступ read-only. `doctor` проверяет и агитирует.
- **Спуфинг cwd**: `allowed_dirs` — UX-барьер против случайного попадания не в
  ту базу, не security boundary.
- **Prompt injection через результаты запросов**: полной защиты не существует
  (продемонстрированные атаки 2026 г.). Митигации: read-only ограничивает blast
  radius, аудит-лог даёт форензику; остальное — ответственность harness'а.
- **Враждебный пользователь-человек**: nyet — инструмент пользователя, а не
  система контроля доступа между людьми.

### Процесс

`SECURITY.md` с контактом для приватных репортов — до первого публичного
релиза. Известные обходы валидатора фиксируются в golden-корпусе.

---

## Журнал решений (июль 2026)

1. Пустой/отсутствующий `allowed_dirs` → **запрещено везде** (fail closed);
   «отовсюду» — явный `allowed_dirs = ["~"]`.
2. Права конфига с group/other-битами → **warning** в stderr + пункт в
   `doctor`, не отказ (не ломаем CI/контейнеры).
3. `pg_sleep` → **deny** (тихий DoS через пул соединений); denylist
   переопределяется в конфиге (`validator.allow_functions`/`deny_functions`).
4. jsonl → **конверт одной JSON-строкой в stderr**, stdout — чистый поток
   строк данных.
5. Redis `COMMAND INFO` → **без кэша**, запрос при коннекте; кэш — только
   как естественное свойство connection daemon (v0.5). Механика получения
   классификации не настраивается — настраивается только policy
   (`allow_commands`/`deny_commands`).
6. Конверт (успех и ошибка) для не-json форматов — **в stderr**; stdout —
   только данные (при ошибке пуст). Место конверта определяется форматом,
   не исходом.
