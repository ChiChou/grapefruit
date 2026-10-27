# IGF Kuna adapter

This leaf crate is copied into the pinned Kuna workspace by `npm run build:kuna`.
It uses Kuna's public engine APIs for one file-backed function or a bounded live
memory snapshot. No LLM, CLI subprocess, or network is used at runtime.

The build compiles and packages only x86 (32/64), ARM (including Thumb), and
AArch64 (including AppleSilicon/ARM64e) SLEIGH languages. Other processors and
16-bit x86 language definitions are excluded. ARM64e uses the AppleSilicon
specification; Thumb snapshots preserve the instruction mode and clear the
entry pointer's mode bit. File inputs retain Kuna's format/ABI detection.

Kuna is pinned in `scripts/build-kuna.ts`. Generated WASM, runtime specifications,
LICENSE, NOTICE, and version metadata go into `gui/public/kuna` and are copied
into the GUI distribution. The source/build cache lives in `.kuna`.

Prerequisite: Rust stable >= 1.90 through rustup with the `wasm32-wasip1` target.
Run `npm run check:decompilers` after building both offline engines.

Live snapshots contain the analyzed function's byte range, at its original
address. Globals, separate literal pools, imports, and callee types outside that
range are unavailable. File-backed decompilation has the complete binary.
