# Installation

## npm (recommended)

Install globally with npm. Requires Node.js 22+ or Bun 1.3.6+.

```
npm install -g igf
```

Then run:

```
igf
```

## Prebuilt Binary

Single executable binaries are available for macOS, Linux, and Windows. No runtime dependencies needed — the binary bundles everything (built with Bun single-file executable).

Download the latest release from [GitHub Releases](https://github.com/chichou/grapefruit/releases):

- `igf-darwin-arm64` — macOS Apple Silicon
- `igf-darwin-x64` — macOS Intel
- `igf-linux-x64` — Linux x86_64
- `igf-windows-x64.exe` — Windows x86_64

### macOS

macOS quarantines files downloaded from the internet. Remove the quarantine attribute before running:

```
chmod +x igf-darwin-arm64
xattr -rc igf-darwin-arm64
./igf-darwin-arm64
```

If you see a "damaged" or "unidentified developer" warning, the `xattr -rc` command above resolves it. This strips the `com.apple.quarantine` extended attribute that Gatekeeper checks.

### Windows

Windows may flag the downloaded binary with a "downloaded from the internet" mark. To remove it:

1. Right-click the `.exe` file
2. Select **Properties**
3. Check **Unblock** at the bottom of the General tab
4. Click **Apply**

Or use PowerShell:

```
Unblock-File .\igf-windows-x64.exe
```

### Linux

Mark the binary as executable and run:

```
chmod +x igf-linux-x64
./igf-linux-x64
```

## Frida Server

Grapefruit requires Frida server running on the target device. Follow the official setup guides:

- [iOS](https://frida.re/docs/ios/)
- [Android](https://frida.re/docs/android/)

### Frida Version

**Frida 17 (latest) is recommended** and used by default. It receives the latest features, bug fixes, and platform support.

Frida 16 is also supported for environments that haven't migrated yet. To use Frida 16, pass the CLI flag or set the environment variable:

```
igf --frida 16
```

Or:

```
FRIDA_VERSION=16 igf
```

> **Note:** Frida 16 support is not as well tested. You may encounter compatibility issues with newer OS versions or missing features that are only available in Frida 17. We recommend upgrading to Frida 17 when possible.

For AI-powered decompilation, see [LLM Configuration](/docs/llm).
