#!/usr/bin/env bash
# SPECULOS_BIN for the speculos crate: runs $SPECULOS_IMAGE instead of a local speculos.
set -euo pipefail
: "${SPECULOS_IMAGE:?SPECULOS_IMAGE must be set (see versions.env)}"
args=(); elf=""
for a in "$@"; do
    if [[ "$a" == *.elf && -f "$a" ]]; then
        elf="$(cd "$(dirname "$a")" && pwd)/$(basename "$a")"; args+=("/app/$(basename "$a")")
    else
        args+=("$a")
    fi
done
[[ -n "$elf" ]] || { echo "speculos-docker.sh: no existing *.elf argument in: $*" >&2; exit 1; }
name="bwk-speculos-$$"
docker run -d --rm --name "$name" --network host -v "$(dirname "$elf")":/app:ro \
    "$SPECULOS_IMAGE" "${args[@]}" >/dev/null
# The crate SIGKILLs this process (docker logs, same pid after exec); then drop the container.
( while kill -0 $$ 2>/dev/null; do sleep 1; done; docker rm -f "$name" >/dev/null 2>&1 ) &
exec docker logs -f "$name"
