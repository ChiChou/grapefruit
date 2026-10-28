# Offline native hook templates

Native hook argument and return types are filled from the SQLite database published by [igf-signatures](https://github.com/ChiChou/igf-signatures). The database covers Android NDK and common AOSP libraries, plus C APIs from Xcode's iOS and macOS SDKs. It also archives Android kernel syscall metadata separately from exported functions.

The dialog uses platform, architecture, module and symbol to select a template. A fallback matched only by symbol name is labelled. Unknown functions remain editable. The original C types are displayed alongside the selected types; templates can always be corrected before confirming the hook.

Each database type keeps its original C spelling, canonical type, Frida type, width and display hint. For example, `const char *` has Frida type `pointer` but defaults to UTF-8 string logging; `void *` defaults to an address. Objective-C object pointers can default to object display. These are editable hints: character pointers can also refer to binary buffers.

Variadic templates provide fixed arguments only. Approximate aggregate conversions are labelled. The built-in interceptor logger does not decode floating-point register arguments or multiword 64-bit arguments on 32-bit targets; custom hook code is appropriate for those values.

## Installation and updates

`npm run setup`, `npm run dev` (including `dev:both` and `dev:all`), and the npm/CLI build commands fetch the pinned release when the local copy is missing or outdated. Build actions also fetch it before packaging. To fetch it independently:

```sh
npm run fetch:signatures
npm run check:signatures
```

`signatures.lock.json` pins the repository, release, compressed artifact checksum and SQLite checksum. The download is verified before installation into `signatures/signatures.db`. npm and SEA packages include that file; installing the published npm package requires no separate database download. Runtime lookup is entirely local and read-only. To update the database, change the lock to a published release using its `manifest.json`, fetch it, then run the checks and tests.

For an air-gapped setup, copy the pinned release artifact and run:

```sh
npm run fetch:signatures -- --file /path/to/signatures.db.gz
```

The database is built in its own repository by macOS GitHub Actions using Xcode's bundled libclang. IGF users need no SDK, compiler, LLM provider or API key. The former `/api/llm` and `/api/llm/stream` endpoints and `LLM_*` configuration have been removed. Agent skills continue to use their host coding agent independently.

## Lookup API

`GET /api/signatures?platform=android&arch=arm64&module=libc.so&name=puts`

`platform` is `android` or `darwin`; `name` is required. `arch` and `module` are optional. The response includes the dataset version and `match`, which is `null` when no template exists. Matched arguments and return types retain raw C spelling, canonical C, Frida type and display hint. A missing database returns HTTP 503 and the GUI keeps manual entry available.
