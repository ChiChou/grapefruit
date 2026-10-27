# IGF DDC adapter

This leaf crate uses DDC's parser and decompiler libraries to render the class
containing a selected DEX method. It runs in a browser WASI worker. APK extraction
remains in IGF; the adapter receives an individual DEX image.

`npm run build:ddc` fetches the pinned source and builds only this adapter and its
library dependencies. It does not build DDC's CLI, REST server, or MCP server.
The build disables DDC's native monitored-thread scheduling on wasm32; the
browser worker instead supplies cancellation and a hard 60-second timeout.
Decompilation algorithms are unchanged.

Artifacts and the upstream MIT license go into `gui/public/ddc`. The source/build
cache lives in `.ddc`. The Rust prerequisite is the same as the Kuna adapter.
