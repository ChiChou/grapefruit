# 分析与反编译

## 交互式反编译器

![分屏视图与控制流图](/radare2.webp)

Grapefruit 内置完全基于浏览器的反编译器，由编译为 WebAssembly 的 radare2 驱动。拖入任意二进制文件——ELF、Mach-O、DEX 或 Hermes 字节码——即刻开始逆向。无需连接设备、无需服务端处理、无需配置。

分屏视图同时展示反汇编和控制流图。可在线性、图形、反编译器和 AI 反编译模式之间切换。在集成工作区中浏览函数、类、字符串和交叉引用。

## 实时反汇编

![原生反汇编](/disasm.webp)

对于实时进程，内存从目标设备按需读取。点击模块或类浏览器中的函数地址，打开反汇编标签页，提供四种视图：

- **线性视图** — 完整函数反汇编，带语法高亮
- **图形视图** — 控制流图，显示基本块及分支走向（绿色为 true，红色为 false，灰色为无条件跳转）
- **反编译器** — 伪 C 反编译输出
- **AI 反编译** — 将反汇编发送给 LLM，生成高质量 C/C++ 重构代码，支持流式输出

## DEX 分析

![DEX 分析](/dex.webp)

从 APK 浏览器或文件系统打开任意 `.dex` 文件：

- **类浏览器** — 列出所有类，展开查看方法和字段，支持搜索
- **方法反汇编** — 点击方法查看 Dalvik 字节码
- **字符串搜索** — 浏览所有字符串，点击查找交叉引用
- **交叉引用** — 点击 xref 跳转到引用方法的反汇编
- **AI 反编译** — 将 Dalvik 字节码反编译为 Java

## Hermes 字节码分析

![Hermes 字节码](/hermes.webp)

使用 Hermes 引擎的 React Native 应用将 JavaScript 编译为私有字节码。Grapefruit 可拦截并分析这些字节码：

- **反汇编** — Hermes 字节码列表，含函数名、参数和大小
- **伪代码** — 基于规则的反编译，重构类似 JavaScript 的语法
- **AI 反编译** — 通过 LLM 重构地道的 JavaScript，还原变量名和 React Native 模式

## AI 反编译

以上所有分析模式均支持 AI 反编译。用环境变量配置 LLM 服务商：

```
LLM_PROVIDER=anthropic   # 或 openai, gemini, openrouter
LLM_API_KEY=sk-...
LLM_MODEL=claude-sonnet-4-20250514
```

发送前会自动精简反汇编以节省 token，并附带函数名和参数信息作为上下文。
