# Instrumentation

## Function Hooking

The hooks panel lets you intercept function calls at runtime using Frida. Select a class and method from the browser, then apply a hook. Hooked calls are logged with arguments and return values.

Hooks support:

- Objective-C method hooking (iOS)
- Java method hooking (Android)
- Native function hooking (both platforms)
- Custom hook scripts with argument/return value modification

## Class Browser

Browse all loaded classes in the target process. On iOS, this includes Objective-C and Swift classes from all loaded frameworks. On Android, all Java/Kotlin classes from the app and its dependencies.

- Search by class name
- Expand classes to view methods and properties
- Click a method to hook or disassemble it

## Module Browser

Lists all loaded dynamic libraries (dylibs on iOS, .so files on Android). Click a module to see its exports — functions and symbols that can be hooked or disassembled.

## Thread Inspector

View all running threads in the target process with their current backtrace. Useful for understanding the threading model and finding where specific operations execute.

## URL Schemes

Inspect registered URL schemes for the app. This is a common attack surface for mobile apps — deep links can trigger sensitive operations if not properly validated.

## Memory Scanner

Search process memory for byte patterns, strings, or specific values. Results show the address and surrounding context. Useful for finding hardcoded secrets, tokens, or data structures in memory.
