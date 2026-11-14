#!/usr/bin/env bash
#
# MuSig2 end-to-end runner: Speculos (Ledger, seed B) and the Coldcard simulator
# (seed C) for tests/musig_devices.rs, torn down on every exit.
#
# Usage:
#   hwi/tests/devices/run.sh [-- <extra cargo test args>]
#
# Environment:
#   SPECULOS_ELF          : Ledger Bitcoin Test ELF for nanosp (LEDGER_APP_VERSION of
#                           tests/speculos/versions.env).
#   COLDCARD_SIM_UNIX_DIR : the `unix` directory of a built Coldcard firmware checkout.
#   COLDCARD_SIM_PYTHON   : a Python with the simulator requirements.
#   BITCOIND_V31_EXE      : a Bitcoin Core v31 bitcoind.
#   LOG_DIR               : where the simulator and Speculos logs go (default
#                           target/devices-logs).
#
# Prerequisites: docker.

set -euo pipefail

SEED_B="legal winner thank year wave sausage worth useful legal winner thank yellow"
SEED_C="letter advice cage absurd amount doctor acoustic avoid letter advice cage above"
CONTAINER=bwk-devices-speculos

if [[ "${1:-}" == "--" ]]; then
    shift
fi
EXTRA_ARGS=("$@")

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

command -v docker >/dev/null || {
    echo "docker not found on PATH" >&2
    exit 1
}
for var in SPECULOS_ELF COLDCARD_SIM_UNIX_DIR COLDCARD_SIM_PYTHON BITCOIND_V31_EXE; do
    [[ -n "${!var:-}" ]] || {
        echo "set $var (see the usage at the top of $0)" >&2
        exit 1
    }
done
[[ -f "$SPECULOS_ELF" ]] || {
    echo "SPECULOS_ELF=$SPECULOS_ELF is not a file" >&2
    exit 1
}
SPECULOS_ELF="$(cd "$(dirname "$SPECULOS_ELF")" && pwd)/$(basename "$SPECULOS_ELF")"

LOG_DIR="${LOG_DIR:-target/devices-logs}"
mkdir -p "$LOG_DIR"
LOG_DIR="$(cd "$LOG_DIR" && pwd)"

# shellcheck disable=SC1091
. tests/speculos/versions.env
[[ "$SPECULOS_IMAGE" == *@sha256:* ]] || {
    echo "SPECULOS_IMAGE=$SPECULOS_IMAGE is not pinned by digest" >&2
    exit 1
}
docker image inspect "$SPECULOS_IMAGE" >/dev/null 2>&1 || docker pull "$SPECULOS_IMAGE"

SIM_PID=""
cleanup() {
    docker logs "$CONTAINER" >"$LOG_DIR/speculos.log" 2>&1 || true
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    if [[ -n "$SIM_PID" ]]; then
        kill -TERM -- -"$SIM_PID" 2>/dev/null || true
        for _ in $(seq 50); do
            kill -0 -- -"$SIM_PID" 2>/dev/null || break
            sleep 0.1
        done
        kill -KILL -- -"$SIM_PID" 2>/dev/null || true
        rm -rf /tmp/cc-simulators/"$SIM_PID" /tmp/ckcc-simulator-"$SIM_PID".sock
    fi
}
trap cleanup EXIT

echo "==> Speculos $SPECULOS_IMAGE"
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$CONTAINER" \
    -p 127.0.0.1:9999:9999 -p 127.0.0.1:5000:5000 \
    -v "$(dirname "$SPECULOS_ELF")":/app:ro \
    "$SPECULOS_IMAGE" \
    --model nanosp --display headless --api-port 5000 --apdu-port 9999 \
    --seed "$SEED_B" "/app/$(basename "$SPECULOS_ELF")" >/dev/null
for _ in $(seq 60); do
    curl -sf http://127.0.0.1:5000/events >/dev/null && break
    sleep 1
done
curl -sf http://127.0.0.1:5000/events >/dev/null || {
    echo "Speculos did not answer on 127.0.0.1:5000 within 60 s" >&2
    exit 1
}

echo "==> Coldcard simulator from $COLDCARD_SIM_UNIX_DIR"
(
    cd "$COLDCARD_SIM_UNIX_DIR"
    SDL_VIDEODRIVER=dummy exec setsid "$COLDCARD_SIM_PYTHON" simulator.py \
        --eff --headless --segregate --seed "$SEED_C"
) </dev/null >"$LOG_DIR/coldcard-sim.log" 2>&1 &
SIM_PID=$!
sleep 1
ps -o pid=,pgid=,cmd= -p "$SIM_PID" | awk -v pid="$SIM_PID" \
    '$1 == pid && $2 == pid && /simulator\.py/ { found = 1 } END { exit !found }' || {
    echo "pid $SIM_PID is not simulator.py leading its own process group:" >&2
    ps -o pid,pgid,cmd -p "$SIM_PID" >&2 || true
    exit 1
}
SOCKET=/tmp/ckcc-simulator-"$SIM_PID".sock
for _ in $(seq 90); do
    [[ -S "$SOCKET" ]] && break
    sleep 1
done
[[ -S "$SOCKET" ]] || {
    echo "no Coldcard simulator socket $SOCKET within 90 s" >&2
    exit 1
}

echo "==> image $SPECULOS_IMAGE"
echo "==> ELF $(sha256sum "$SPECULOS_ELF")"
echo "==> $("$BITCOIND_V31_EXE" --version | head -1)"

export BWK_COLDCARD_SIMULATOR="$SOCKET"
export SPECULOS_APDU=127.0.0.1:9999
export SPECULOS_API=127.0.0.1:5000
export BITCOIND_V31_EXE
cargo test -p bwk-hwi --features musig --test musig_devices -- \
    --ignored --nocapture --test-threads=1 \
    "${EXTRA_ARGS[@]}"
