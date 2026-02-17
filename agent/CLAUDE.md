This folder is the frida agent source code.

## Test a single RPC:

frida -U -F -l src/droid/index.ts -e 'rpc.exports.invoke("manifest", "xml", [])' -q

## Build

`bun run build` can build all agents, types at once. But sometimes you just need
to build a paricular agent, for example `bun run build:droid` or `bun run build:fruity`
