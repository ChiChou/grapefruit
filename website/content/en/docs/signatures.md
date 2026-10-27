# Offline Hook Templates

Native hook types are filled from a local SQLite database generated from Android NDK, AOSP and Xcode SDK declarations. No provider configuration or API key is needed.

The dialog matches the platform, architecture, library and exported symbol. Templates remain editable, including when a symbol is unknown or only matched by name. Original C types are shown alongside the selected types.

A `const char *` retains the Frida type `pointer`, with a UTF-8 string display hint. Ordinary pointers display as addresses. Object pointers can use Objective-C display. Change the selection when a pointer refers to binary data or another kind of object.

Variadic templates contain fixed parameters only. Approximate types are labelled. Floating-point registers, aggregates and multiword arguments can require custom hook code.

The database is maintained in [igf-signatures](https://github.com/ChiChou/igf-signatures). IGF pins a release and verifies checksums during setup; installed packages perform all lookups locally. Source checkouts can install it with `npm run fetch:signatures`.
