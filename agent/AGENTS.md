This folder is the frida agent source code.

## Test a single RPC:

Build the agent first, then load the compiled Frida script:

`npm run build:droid`

`frida -U -F -l dist/droid.js -e 'rpc.exports.invoke("info", "processInfo", [])' -q`

If the RPC returns a Promise, use

`frida -U -F -l dist/droid.js -e 'rpc.exports.invoke("manifest", "xml", []).then(result => console.log(result)).catch(err => console.error(err))' -q`

## Build

`npm run build` can build all agents and types at once. But sometimes you just need
to build a particular agent, for example `npm run build:droid` or `npm run build:fruity`.
