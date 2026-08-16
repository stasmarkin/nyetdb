# Where testcontainers looks for Docker: an explicit DOCKER_HOST wins, else
# colima's socket, else docker's own default (so this is a no-op elsewhere).
colima_sock := env('HOME') / '.colima/docker.sock'
docker_host := env('DOCKER_HOST', '')
export DOCKER_HOST := if docker_host != '' { docker_host } else if path_exists(colima_sock) == 'true' { 'unix://' + colima_sock } else { 'unix:///var/run/docker.sock' }

# The unit tests in src/engine.rs that start containers — the rest of --bins and
# all of --test cli need no Docker. Add yours here if you write another.
# `differential_` is a prefix skip: it also drops the SQLite differential test,
# which needs no Docker — the four are one experiment and belong in one run.
container_units := '--skip differential_ ' + \
  '--skip postgres_layer2_types_and_timeout ' + \
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
    # --test docs reads markdown and nothing else, so the docs stay in the fast
    # loop: a rename that breaks a cross-reference fails here, not in review.
    cargo test --lib --bins --test cli --test docs -- {{ container_units }}

# Everything, containers included (~40s): needs a Docker daemon.
test: _docker
    cargo test

# Mutation-tests the validator's security boundary (~12 min, no Docker).
# Manual / pre-release only, NOT per-PR CI: it's heavy and needs a stable
# baseline. Scoped to src/validator.rs, container tests skipped so it stays
# Docker-free. Needs `cargo install cargo-mutants`.
mutants:
    cargo mutants --file src/validator.rs -j 6 -- --lib --bins --test cli -- {{ container_units }}

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

# Why this is not just `npm publish` on the release artifact: dist ships an
# `npm-shrinkwrap.json` pinning axios 1.7.9 and its 2024 dependency tree, and a
# shrinkwrap is authoritative for whoever installs — so every user would get
# 1 critical + 4 high advisories that `npm audit fix` in THEIR project cannot
# override. The caret ranges in package.json are fine; only the lockfile is
# stale. This regenerates it, refuses to publish if anything is still
# vulnerable, and publishes that. The tarball on npm therefore differs from the
# one attached to the release — by its lockfile, and nothing else.
#
# --ignore-scripts: the package's own postinstall downloads a platform binary,
# which has no business running here. The registry is spelled out because a
# company registry in ~/.npmrc would otherwise quietly take this package.

# Publishes the npm wrapper for an already-released tag (`just npm-publish 0.3.1`).
npm-publish version:
    #!/usr/bin/env bash
    set -euo pipefail
    work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT
    gh release download "v{{ version }}" -R stasmarkin/nyetdb -p 'nyetdb-npm-package.tar.gz' -D "$work"
    tar xf "$work/nyetdb-npm-package.tar.gz" -C "$work"
    cd "$work/package"
    test "$(jq -r .version package.json)" = "{{ version }}"
    rm -f npm-shrinkwrap.json
    npm install --registry https://registry.npmjs.org --ignore-scripts --no-audit --no-fund
    npm audit --registry https://registry.npmjs.org --audit-level=low
    npm shrinkwrap
    npm publish --registry https://registry.npmjs.org --access public

# Readable line instead of a testcontainers stack trace when Docker is down.
[private]
_docker:
    @docker info >/dev/null 2>&1 || { echo "no Docker daemon at $DOCKER_HOST — start one (\`colima start\`, or launch Docker Desktop), or run \`just test-fast\` for the container-free tests" >&2; exit 1; }
