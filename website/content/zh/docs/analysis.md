# 分析与反编译

## 原生反汇编

反汇编引擎在服务器端以 WebAssembly 模块（WASI）形式运行 radare2。点击模块或类浏览器中的函数地址，Grapefruit 会打开一个包含四个视图的反汇编标签页：

- **线性视图** — 完整函数反汇编，通过 ANSI 转 HTML 转换进行语法着色
- **图形视图** — 使用 dagre 布局的控制流图（CFG），显示基本块及跳转/失败边
- **反编译器视图** — radare2 内置的伪 C 反编译器输出
- **AI 反编译** — 将反汇编代码发送给 LLM，生成高质量 C/C++ 重构代码，支持流式输出

对于实时进程，内存按需映射——引擎在分析过程中发现基本块时会迭代地从目标进程获取页面。

## DEX 分析

从 APK 浏览器或文件系统打开任意 `.dex` 文件。Grapefruit 会将文件下载到服务器端并加载到 radare2 会话中。

- **类浏览器** — 列出 `ic` 输出的所有类。展开类可查看其方法和字段。支持按类名搜索。
- **方法反汇编** — 点击方法查看其 Dalvik 字节码。radare2 原生处理所有指令解码。
- **字符串搜索** — 浏览 DEX 文件中的所有字符串。点击字符串可查找交叉引用（哪些方法使用了它）。
- **交叉引用** — 点击 xref 可直接跳转到引用方法的反汇编。
- **AI 反编译** — 使用 LLM 将 Dalvik 字节码反编译为 Java。

## Hermes 字节码分析

使用 Hermes 引擎的 React Native 应用将 JavaScript 编译为私有字节码。Grapefruit 在运行时拦截 Hermes 字节码，提供：

- **反汇编** — 原始 Hermes 字节码列表，含函数名、参数数量和大小
- **伪代码** — 来自 r2hermes 的基于规则的反编译，从字节码重构类似 JavaScript 的语法
- **AI 反编译** — 将伪代码和反汇编发送给 LLM，重构带有正确变量名、React/RN 模式和简化控制流的地道 JavaScript

## AI 反编译

三种分析模式（原生、DEX、Hermes）都支持 AI 反编译。用环境变量配置 LLM 服务商：

```
LLM_PROVIDER=anthropic   # 或 openai, gemini, openrouter
LLM_API_KEY=sk-...
LLM_MODEL=claude-sonnet-4-20250514
```

发送前会先精简反汇编（去除地址、管道符、文件头）以节省 token 并降低延迟。符号表中的函数名和参数数量也会一并发送，作为上下文参考。

## 控制流图

图形视图从 radare2 的 `agfj` 命令中提取基本块和边，并使用 dagre 进行自动布局。条件分支用不同颜色显示 true/false 边。
