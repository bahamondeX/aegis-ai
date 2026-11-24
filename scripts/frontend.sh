#!/bin/sh
set -eu

pin="$(cat .nvmrc)"
project_node="data/toolchain/node-$pin/bin"
nvm_node="${NVM_DIR:-$HOME/.nvm}/versions/node/v$pin/bin"
if [ -x "$project_node/node" ]; then
    PATH="$(pwd)/$project_node:$PATH"
elif [ -x "$nvm_node/node" ]; then
    PATH="$nvm_node:$PATH"
fi
export PATH
test "$(node --version)" = "v$pin"
version="$(cat .pnpm-version)"
exec npx --yes --package=corepack@0.34.6 corepack "pnpm@$version" --dir frontend "$@"
