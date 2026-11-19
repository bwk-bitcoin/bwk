#!/bin/bash

# The single definition of what "green" means for this repo. Every CI job and
# every local check runs a section of this script, so a change to the feature
# set or the flags applies everywhere at once.
#
# Usage: ci-checks.sh [fmt|clippy|tests|per-commit-lint|build-test-bins|
#                      run-test-bins|doc-tests|p2p-tests|build|default-build]
# With no section, runs fmt, clippy, tests and build in order.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || (cd "$SCRIPT_DIR/.." && pwd))"
cd "$REPO_ROOT"

# test and sqlite are built explicitly: both gate large amounts of code that a
# default build never compiles, so breakage there goes unnoticed. sqlite gates
# its backend and that backend's tests; test gates the integration test files
# and the test-only constructors they reach for.
FEATURES="test,sqlite"

# `test` gates test-only code a consumer never compiles, so the release build
# must be checked without it.
BUILD_FEATURES="sqlite"

run_fmt() {
    echo "=== fmt check ==="
    cargo fmt --all -- --check
}

run_clippy() {
    echo "=== clippy ==="
    cargo clippy --all-targets --features "$FEATURES" -- -D warnings
}

run_tests() {
    echo "=== tests ==="
    # Run integration tests single-threaded: each spins up its own bitcoind/blindbit
    # (and electrsd) regtest daemon, and running dozens concurrently starves CPU/IO,
    # causing flaky sync timeouts and wallet-state races (e.g. spurious -6 "Insufficient
    # funds" after invalidateblock). One daemon set at a time trades runtime for reliability.
    cargo test --features "$FEATURES" --verbose --color always -- --nocapture --test-threads=1
}

run_per_commit_lint() {
    run_fmt
    run_clippy
}

run_build_test_bins() {
    local archive copied metadata_file msg_file records_file stage_dir test_manifest tmp_root
    tmp_root="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
    msg_file="$(mktemp "$tmp_root/cargo-test-json.XXXXXX")"
    metadata_file="$(mktemp "$tmp_root/cargo-metadata.XXXXXX")"
    records_file="$(mktemp "$tmp_root/cargo-test-records.XXXXXX")"
    stage_dir="$(mktemp -d "$tmp_root/cargo-test-artifact.XXXXXX")"
    test_manifest="${CARGO_TARGET_DIR:-$REPO_ROOT/target}/tests.tsv"
    archive="${TEST_ARTIFACT_FILE:-$REPO_ROOT/test-bins.tar.gz}"
    trap "rm -rf '$msg_file' '$metadata_file' '$records_file' '$stage_dir'" EXIT

    echo "=== build test binaries ==="
    cargo metadata --format-version 1 > "$metadata_file"
    cargo test --features "$FEATURES" --verbose --color always --no-run --message-format=json \
        | tee "$msg_file"

    jq -r --slurpfile metadata "$metadata_file" '
        select(.reason == "compiler-artifact")
        | select(.executable != null)
        | select(.profile.test == true)
        | .package_id as $package_id
        | ($metadata[0].packages[] | select(.id == $package_id)) as $package
        | [.executable, $package.manifest_path, $package.name]
        | @tsv
    ' "$msg_file" > "$records_file"

    mkdir -p "$(dirname "$test_manifest")"
    case "$test_manifest" in
        "$HOME"/*) ;;
        *) echo "test manifest is outside HOME: $test_manifest" >&2; exit 1 ;;
    esac
    : > "$test_manifest"
    copied=0
    while IFS=$'\t' read -r executable manifest_path package; do
        local artifact_executable package_dir
        package_dir="$(dirname "${manifest_path#"$REPO_ROOT/"}")"
        case "$executable" in
            "$HOME"/*) ;;
            *) echo "test binary is outside HOME: $executable" >&2; exit 1 ;;
        esac
        artifact_executable="$stage_dir/${executable#"$HOME/"}"
        mkdir -p "$(dirname "$artifact_executable")"
        cp "$executable" "$artifact_executable"
        strip --strip-debug "$artifact_executable"
        printf '%s\t%s\t%s\n' "$package" "${executable#"$HOME/"}" "$package_dir" >> "$test_manifest"
        copied=$((copied + 1))
    done < "$records_file"
    if [ "$copied" -eq 0 ]; then
        echo "no test binaries found in cargo output" >&2
        exit 1
    fi

    mkdir -p "$stage_dir/$(dirname "${test_manifest#"$HOME/"}")"
    cp "$test_manifest" "$stage_dir/${test_manifest#"$HOME/"}"
    shopt -s globstar nullglob
    for runtime_file in "${CARGO_TARGET_DIR:-$REPO_ROOT/target}"/debug/build/*/out/**/*; do
        if [ -f "$runtime_file" ] && [ -x "$runtime_file" ]; then
            mkdir -p "$stage_dir/$(dirname "${runtime_file#"$HOME/"}")"
            cp "$runtime_file" "$stage_dir/${runtime_file#"$HOME/"}"
        fi
    done
    for runtime_file in "${CARGO_HOME:-$HOME/.cargo}"/git/checkouts/blindbitd-*/**/bin/*; do
        if [ -f "$runtime_file" ] && [ -x "$runtime_file" ]; then
            mkdir -p "$stage_dir/$(dirname "${runtime_file#"$HOME/"}")"
            cp "$runtime_file" "$stage_dir/${runtime_file#"$HOME/"}"
        fi
    done
    tar -C "$stage_dir" --create --gzip --file "$archive" .
}

run_test_bins() {
    local archive package package_dir ran requested_package rust_lib_dir selected test_manifest
    local -a packages
    if [ -z "${TEST_PACKAGES:-}" ]; then
        echo "TEST_PACKAGES must be set" >&2
        exit 1
    fi
    echo "=== tests: $TEST_PACKAGES ==="
    archive="${TEST_ARTIFACT_FILE:-$REPO_ROOT/test-bins.tar.gz}"
    tar -C "$HOME" --extract --gzip --file "$archive"
    test_manifest="${CARGO_TARGET_DIR:-$REPO_ROOT/target}/tests.tsv"
    if [ ! -f "$test_manifest" ]; then
        echo "missing test manifest: $test_manifest" >&2
        exit 1
    fi
    IFS=',' read -r -a packages <<< "$TEST_PACKAGES"
    rust_lib_dir="$(rustc --print target-libdir)"
    ran=0
    while IFS=$'\t' read -r package executable package_dir; do
        selected=false
        for requested_package in "${packages[@]}"; do
            if [ "$requested_package" = "workspace-rest" ]; then
                if [ "$package" != "bwk" ] && [ "$package" != "bwk-sp" ]; then
                    selected=true
                    break
                fi
            elif [ "$package" = "$requested_package" ]; then
                selected=true
                break
            fi
        done
        if [ "$selected" = false ]; then
            continue
        fi
        ran=$((ran + 1))
        (
            export LD_LIBRARY_PATH="$rust_lib_dir:${LD_LIBRARY_PATH:-}"
            cd "$REPO_ROOT/$package_dir"
            "$HOME/$executable" --nocapture --test-threads=1
        )
    done < "$test_manifest"
    if [ "$ran" -eq 0 ]; then
        echo "none of these packages exist in this commit: $TEST_PACKAGES"
        exit 1
    fi
}

run_doc_tests() {
    local test_dir tmp_root test_tmp_dir
    tmp_root="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
    test_dir="$(mktemp -d "$tmp_root/bwk-test-bins.XXXXXX")"
    test_tmp_dir="$test_dir/tmp"
    mkdir -p "$test_tmp_dir"
    trap "rm -rf '$test_dir'" EXIT
    export TMPDIR="$test_tmp_dir"

    echo "=== doc tests ==="
    cargo test --doc --target-dir "$test_dir/doc-target" --features "$FEATURES" --verbose --color always -- --nocapture
}

run_p2p_tests() {
    echo "=== p2p tests ==="
    cargo test -p bwk-p2p --features ci-p2p --verbose --color always -- --nocapture --test-threads=1
}

run_build() {
    echo "=== build ==="
    cargo build --release --features "$BUILD_FEATURES"
    run_qr_feature_builds
}

# The workspace build compiles bwk-qr with all its features only, so a cfg slip
# in a smaller set would go unnoticed. The script from the tip also runs on
# earlier commits, which may predate bwk-qr.
run_qr_feature_builds() {
    local features
    if [ ! -f qr/Cargo.toml ]; then
        return
    fi
    for features in gen scan bbqr; do
        echo "=== bwk-qr build: $features ==="
        cargo build --release -p bwk-qr --no-default-features --features "$features"
    done
}

run_default_build() {
    echo "=== default build ==="
    cargo build --release
}

case "${1:-all}" in
    fmt) run_fmt ;;
    clippy) run_clippy ;;
    tests) run_tests ;;
    per-commit-lint) run_per_commit_lint ;;
    build-test-bins) run_build_test_bins ;;
    run-test-bins) run_test_bins ;;
    doc-tests) run_doc_tests ;;
    p2p-tests) run_p2p_tests ;;
    build) run_build ;;
    default-build) run_default_build ;;
    all)
        echo "=== Commit under test ==="
        git log -1 --oneline
        run_fmt
        run_clippy
        run_tests
        run_build
        run_default_build
        ;;
    *)
        echo "usage: $(basename "$0") [fmt|clippy|tests|per-commit-lint|build-test-bins|run-test-bins|doc-tests|p2p-tests|build|default-build]" >&2
        exit 1
        ;;
esac
