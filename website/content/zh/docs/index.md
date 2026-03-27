# Grapefruit 文档

Grapefruit 是一款面向 iOS 和 Android 的运行时移动安全研究工具，提供浏览器界面进行动态插桩、二进制分析和数据审查。

本项目是 [Passionfruit](https://github.com/chaitin/passionfruit) 的精神继承者，从零重写，采用现代技术栈大幅扩展了功能范围。

## 快速开始

```
npx igf
```

在浏览器中打开终端输出的地址。预编译二进制和其他安装方式见[安装指南](/cn/docs/install)。

## 功能索引

- [安装](/docs/install) — npm、预编译二进制、平台特定配置
- [已知限制](/docs/limits) — 这款工具不做什么
- [分析与反编译](/docs/analysis) — 原生反汇编、DEX 类浏览、Hermes 反编译器、AI 反编译、控制流图
- [动态插桩](/docs/instrumentation) — 函数 Hook、类/方法浏览、模块列表、线程检查
- [文件浏览器与预览](/docs/files) — 文件系统导航、十六进制查看、SQLite 编辑器、plist 查看器、图片/音频/字体预览
- [数据审查](/docs/data) — keychain/keystore、网络监控、加密拦截、隐私审计
- [平台功能](/docs/platforms) — iOS（entitlements、Info.plist、XPC、JSContext）和 Android（APK 浏览、内容提供器、JNI 追踪、资源）
- [LLM 配置](/docs/llm) — 配置 Anthropic、OpenAI、Gemini 或 OpenRouter 实现 AI 反编译

## 架构

Grapefruit 以本地服务器方式运行，由三个组件构成：

- **Server** — Node.js/Bun 进程，管理 Frida 会话并提供 Web UI
- **Agent** — Frida Agent，注入目标应用实现运行时插桩
- **GUI** — React 前端，带可停靠面板、代码编辑器和终端视图

## 环境要求

- Node.js 22+ 或 Bun 1.1+
- 已越狱的 iOS 设备或已 Root 的 Android 设备
- 目标设备上运行有 Frida server
- 可选：LLM API Key 用于 AI 反编译——见 [LLM 配置](/docs/llm)
