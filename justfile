# Where testcontainers looks for Docker: an explicit DOCKER_HOST wins, else
# colima's socket, else docker's own default (so this is a no-op elsewhere).
colima_sock := env('HOME') / '.colima/docker.sock'
docker_host := env('DOCKER_HOST', '')
export DOCKER_HOST := if docker_host != '' { docker_host } else if path_exists(colima_sock) == 'true' { 'unix://' + colima_sock } else { 'unix:///var/run/docker.sock' }

# The unit tests in src/engine.rs that start containers — the rest of --bins and
# all of --test cli need no Docker. Add yours here if you write another.
container_units := '--skip postgres_layer2_types_and_timeout ' + \
  '--skip pg_collapsed_guardrail_arming_keeps_its_invariants ' + \
  '--skip mysql_layer2_types_and_timeout ' + \
  '--skip mysql8_caching_sha2_password_over_tls ' + \
  '--skip mariadb_server_timeout_maps_to_timeout'

# Lists the recipes.
default:
    @just --list

# Debug build (binary: target/debug/nyet).
build:
    cargo build

# Unit + cli tests, no containers, no Docker needed (seconds).
test-fast:
    # --lib as well as --bins: the modules, and their unit tests, live in the
    # lib target since src/lib.rs; only the cli layer is left in the binary.
    cargo test --lib --bins --test cli -- {{ container_units }}

# Everything, containers included (~40s): needs a Docker daemon.
test: _docker
    cargo test

# Pre-commit gate: format, lints, full tests, supply chain.
check: _docker
    cargo fmt --check
    cargo clippy --all-targets -- -D warnings
    cargo test
    cargo deny check
    cargo audit

# Fuzz one target for TIME seconds (needs nightly + `cargo install cargo-fuzz`).
fuzz target time="120":
    # fuzz/seeds/ goes SECOND, so libFuzzer treats it as read-only and writes
    # what it discovers into the gitignored fuzz/corpus/. Same flags as fuzz.yml.
    @mkdir -p fuzz/corpus/{{ target }}
    cargo +nightly fuzz run {{ target }} fuzz/corpus/{{ target }} fuzz/seeds/{{ target }} -- \
        {{ if target == "sql_validate" { "-dict=fuzz/sql.dict" } else { "" } }} \
        -max_total_time={{ time }} -max_len=4096 -timeout=25

# Installs the `nyet` binary into ~/.cargo/bin.
install:
    cargo install --path . --locked

# Readable line instead of a testcontainers stack trace when Docker is down.
[private]
_docker:
    @docker info >/dev/null 2>&1 || { echo "no Docker daemon at $DOCKER_HOST — start one (\`colima start\`, or launch Docker Desktop), or run \`just test-fast\` for the container-free tests" >&2; exit 1; }
