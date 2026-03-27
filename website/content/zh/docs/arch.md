# 架构设计

本文档面向希望深入了解 Grapefruit 工作原理的高级用户，涵盖设计决策和实现细节。

## 为什么用浏览器界面？

传统移动安全工具都在终端运行。Grapefruit 选择浏览器解决了几个问题：

**天然跨平台** — Frida 通过 USB 或 TCP 连接 iOS 和 Android。浏览器界面在用户的本地机器（macOS、Windows、Linux）上运行，设备端无需额外配置。

**丰富的交互** — 交互式控件、语法高亮的代码、十六进制转储、可折叠树状视图在终端里都很别扭。浏览器可以提供组件，而无需打包一套 GUI 工具链。

**多窗口工作空间** — 可停靠面板布局让你把反汇编、Hook 日志、终端视图并排放置。

## 三层架构

```
浏览器 (React) ←→ 服务器 (Node.js/Bun) ←→ 设备 (Frida Agent)
```

- **前端** — React 单页应用。通过 Socket.IO 与服务器通信（实时事件），通过 REST API 进行文件传输。
- **服务器** — 管理 Frida 会话，在前端和 Agent 之间代理 RPC 调用，并将 Hook/加密/网络日志存入 SQLite。
- **Agent** — 注入目标应用的 TypeScript 代码。通过 Frida 的 RPC 机制暴露检查、Hook 和数据提取模块。

## Frida Agent 设计

### 两个 Agent，同一套模式

Grapefruit 打包两个独立的 Agent — iOS 用 (`fruity`) 和 Android 用 (`droid`)。均从 TypeScript 编译而来，通过 `frida-compile` 构建并加载到目标进程。

尽管平台分离，两个 Agent 共享同一套 RPC 模式：

```typescript
rpc.exports = {
  invoke(namespace, method, args)   // 路由到正确的模块
  interfaces()                      // 列出所有可用方法
  restore(rules)                    // 重连时重新应用保存的 Hook
  snapshot()                        // 捕获活跃 Hook 以便持久化
}
```

### 模块注册表

每个 Agent 定义一个静态路由器，将命名空间名称映射到模块对象：

```typescript
// fruity/router.ts
export default { checksec, classdump, cookies, crypto, fs, keychain, ... }
```

调用 `invoke("fs", "ls", ["/"])` 时，注册表查找 `route.fs.ls` 并执行。这让 RPC 接口保持扁平可扩展 — 新增模块只需在路由器中注册即可。

### 类型共享

Agent 方法签名在 TypeScript 中定义。构建后，`tsgo` 生成类型定义供前端直接导入。RPC 代理将这些包装为 async promise，因此在前端调用 `rpc.fs.ls("/")` 时会完全基于 Agent 实际实现的类型检查。

## 分析引擎

### 浏览器里的 radare2

原生代码反汇编在服务器上以 WebAssembly 模块形式运行 radare2。这样无需附带原生二进制文件即可处理 ARM/x86 反汇编、控制流图和 DEX 分析，所有平台依赖都由 WASM 处理。

对于实时进程，内存页在分析过程中按需从目标获取。这样可以立即开始检查代码，而不必等待完整内存 dump。

### Hermes 字节码

使用 Hermes 编译的 React Native 应用采用私有字节码格式。Grapefruit 在运行时拦截 Hermes 字节码，使用 [r2hermes](https://github.com/radareorg/r2hermes)（一个 C11 库）进行反汇编并生成伪代码。对于 AI 反编译，会同时将原始字节码和生成的伪代码发送给 LLM，供其交叉参考两种表示。

## 数据存储

Grapefruit 没有项目或工作空间概念 — 所有数据全局存储，以设备 ID 和目标 bundle/PID 区分。这简化了 UI，但也意味着不同应用 session 共享同一存储目录。

Hook 日志、加密追踪、网络请求和 JNI 追踪通过 Drizzle ORM 存入 SQLite。Pin（Hook 规则）快照以 JSON 文件存储，可快速重新加载。
