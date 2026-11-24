#!/bin/sh
set -eu

platform="$(uname -s)-$(uname -m)"
printf 'Host %s\n' "$platform"
case "$platform" in
    Darwin-arm64) ;;
    *) printf 'Expected native Apple Silicon tooling\n' >&2; exit 1 ;;
esac

df -h .
uv --version
uv python find 3.12
python312="$(uv python find 3.12)"
"$python312" -c 'import platform; assert platform.machine() == "arm64"; print(platform.python_version())'
aws --version

node_pin="$(cat .nvmrc)"
node_home="${NVM_DIR:-$HOME/.nvm}/versions/node/v$node_pin/bin"
if [ -x "data/toolchain/node-$node_pin/bin/node" ]; then
    PATH="$(pwd)/data/toolchain/node-$node_pin/bin:$PATH"
    export PATH
elif [ -x "$node_home/node" ]; then
    PATH="$node_home:$PATH"
    export PATH
fi
test "$(node --version)" = "v$node_pin"
node -p 'JSON.stringify({node:process.version, architecture:process.arch})'
test "$(node -p 'process.arch')" = arm64
# pnpm is pinned for G5. G1 reports availability without installing a package manager.
printf 'Frontend pnpm pin %s\n' "$(cat .pnpm-version)"
if command -v pnpm >/dev/null 2>&1; then
    pnpm --version
elif command -v corepack >/dev/null 2>&1; then
    corepack --version
else
    printf 'pnpm and Corepack unavailable for later frontend setup\n'
fi
if [ -f .env ]; then
    test "$(stat -f '%Lp' .env)" = 600
    git check-ignore -q .env
fi
