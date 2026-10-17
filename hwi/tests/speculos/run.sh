#!/usr/bin/env bash
#
# Local Speculos integration runner. Mirrors the CI `ledger_app` + `speculos`
# jobs in .github/workflows/main.yml so the same app version, builder image and
# Speculos image (all pinned in versions.env) are used in both places.
#
# Usage:
#   tests/speculos/run.sh [nanox|nanosp] [-- <cargo test args>]
#
#   device : nanox (default) | nanosp
#
# Examples:
#   tests/speculos/run.sh                       # nanox, all ignored tests
#   tests/speculos/run.sh nanosp -- speculos_master_fingerprint
#
# Environment:
#   SPECULOS_ELF : prebuilt Ledger Bitcoin Test ELF of LEDGER_APP_VERSION for the
#                  device; skips the build.
#   SPECULOS_BIN : what the speculos crate spawns; defaults to
#                  tests/speculos/speculos-docker.sh (runs SPECULOS_IMAGE).
#
# Caching: built .elf binaries are stored in target/speculos-cache/<device>/
# keyed by app version + builder image. Bumping versions.env invalidates them.
#
# Prerequisites: docker.

set -euo pipefail

DEVICE="${1:-nanox}"
shift || true
if [[ "${1:-}" == "--" ]]; then
    shift
fi
EXTRA_ARGS=("$@")

case "$DEVICE" in
    nanox)  SDK_VAR=NANOX_SDK ;;
    nanosp) SDK_VAR=NANOSP_SDK ;;
    *)
        echo "unknown device: $DEVICE (expected: nanox, nanosp)" >&2
        echo "stax / flex are supported by the speculos crate but not yet wired into these tests." >&2
        exit 1
        ;;
esac

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

command -v docker >/dev/null || {
    echo "docker not found on PATH" >&2
    exit 1
}

# shellcheck disable=SC1091
set -a; . tests/speculos/versions.env; set +a
export SPECULOS_IMAGE

mkdir -p target/speculos-cache

# Ledger Bitcoin app ELF: prebuilt, or built with the pinned builder (cached).
if [[ -n "${SPECULOS_ELF:-}" ]]; then
    [[ -f "$SPECULOS_ELF" ]] || {
        echo "SPECULOS_ELF=$SPECULOS_ELF is not a file" >&2
        exit 1
    }
    ELF="$(cd "$(dirname "$SPECULOS_ELF")" && pwd)/$(basename "$SPECULOS_ELF")"
    echo "==> Using prebuilt $SPECULOS_ELF"
else
    CACHE_KEY="${LEDGER_APP_VERSION}_$(echo "$LEDGER_APP_BUILDER_IMAGE" | tr -c '[:alnum:]' '_')"
    CACHE_DIR="target/speculos-cache/$DEVICE/$CACHE_KEY"
    ELF="$ROOT/$CACHE_DIR/app.elf"
    if [[ ! -f "$ELF" ]]; then
        echo "==> Building Ledger Bitcoin app $LEDGER_APP_VERSION for $DEVICE"
        BUILD_DIR="$(mktemp -d -p target speculos-build.XXXXXX)"
        trap 'rm -rf "$BUILD_DIR"' EXIT
        git clone --branch "$LEDGER_APP_VERSION" --depth 1 \
            https://github.com/LedgerHQ/app-bitcoin-new.git "$BUILD_DIR/app-bitcoin-new"
        docker run --rm -e CPATH=/app/src -e SDK_VAR="$SDK_VAR" -e JOBS="${CARGO_BUILD_JOBS:-6}" \
            -u "$(id -u):$(id -g)" -v "$ROOT/$BUILD_DIR/app-bitcoin-new:/app" -w /app \
            "$LEDGER_APP_BUILDER_IMAGE" \
            bash -c 'make -j"$JOBS" BOLOS_SDK="${!SDK_VAR}" COIN=bitcoin_testnet'
        mkdir -p "$CACHE_DIR"
        cp "$BUILD_DIR/app-bitcoin-new/bin/app.elf" "$ELF"
        echo "==> Cached $ELF"
    else
        echo "==> Using cached $ELF"
    fi
fi

# Speculos runs from the pinned image through the wrapper, unless overridden.
export SPECULOS_BIN="${SPECULOS_BIN:-$ROOT/tests/speculos/speculos-docker.sh}"
docker image inspect "$SPECULOS_IMAGE" >/dev/null 2>&1 || docker pull "$SPECULOS_IMAGE"
echo "==> Using speculos: $SPECULOS_BIN ($SPECULOS_IMAGE)"

# Remove Speculos containers left by a run that was killed mid-flight.
docker ps -aq --filter name=bwk-speculos- | xargs -r docker rm -f >/dev/null

# Run the ignored speculos tests; a filter in EXTRA_ARGS applies to both binaries.
export SPECULOS_ELF="$ELF"
export SPECULOS_MODEL="$DEVICE"
echo "==> SPECULOS_ELF=$SPECULOS_ELF SPECULOS_MODEL=$SPECULOS_MODEL"
cargo test --features ledger --test ledger_speculos -- \
    --ignored --nocapture --test-threads=1 \
    "${EXTRA_ARGS[@]}"
cargo test --features ledger,musig --test ledger_musig_speculos -- \
    --ignored --nocapture --test-threads=1 \
    "${EXTRA_ARGS[@]}"
