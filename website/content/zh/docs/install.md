# 安装

## npm（推荐）

使用 npm 全局安装。需要 Node.js 22+ 或 Bun 1.3.6+。

```
npm install -g igf
```

然后运行：

```
igf
```

## 预编译二进制

提供 macOS、Linux 和 Windows 的单文件可执行程序。无需运行时依赖——二进制文件打包了一切（由 Bun 单文件可执行构建）。

从 [GitHub Releases](https://github.com/chichou/grapefruit/releases) 下载最新版本：

- `igf-darwin-arm64` — macOS Apple Silicon
- `igf-darwin-x64` — macOS Intel
- `igf-linux-x64` — Linux x86_64
- `igf-windows-x64.exe` — Windows x86_64

### macOS

macOS 会对从互联网下载的文件进行隔离。运行前需移除隔离属性：

```
chmod +x igf-darwin-arm64
xattr -rc igf-darwin-arm64
./igf-darwin-arm64
```

如果看到"文件已损坏"或"无法确认开发者"警告，上述 `xattr -rc` 命令可以解决。该命令会移除 Gatekeeper 检查的 `com.apple.quarantine` 扩展属性。

### Windows

Windows 可能会对下载的二进制文件标记"来自互联网"。移除方法：

1. 右键点击 `.exe` 文件
2. 选择**属性**
3. 在"常规"选项卡底部勾选**解除锁定**
4. 点击**应用**

或使用 PowerShell：

```
Unblock-File .\igf-windows-x64.exe
```

### Linux

给二进制文件添加执行权限后运行：

```
chmod +x igf-linux-x64
./igf-linux-x64
```

## Frida Server

Grapefruit 需要在目标设备上运行 Frida server。按官方指南配置：

- [iOS](https://frida.re/docs/ios/)
- [Android](https://frida.re/docs/android/)

### Frida 版本

**推荐使用 Frida 17（最新版）**，这也是默认版本。它包含最新的功能、修复和平台支持。

如果你的环境尚未迁移到 Frida 17，也可以使用 Frida 16。通过命令行参数或环境变量切换：

```
igf --frida 16
```

或者：

```
FRIDA_VERSION=16 igf
```

> **注意：** Frida 16 的支持测试覆盖较少，可能在新版操作系统上遇到兼容性问题，且缺少仅在 Frida 17 中提供的新功能。建议尽早升级到 Frida 17。

如需 AI 反编译功能，参见 [LLM 配置](/docs/llm)。
