# 离线 Hook 模板

原生 Hook 类型从本地 SQLite 数据库自动填写。数据库由 Android NDK、AOSP 和 Xcode SDK 的声明生成，无需配置模型供应商或 API Key。

对话框按平台、架构、库名及导出符号匹配模板，并显示原始 C 类型。模板始终可以修改；未知符号可手动填写，仅按符号名称匹配时会显示提示。

例如，`const char *` 的 Frida 类型仍是 `pointer`，但默认以 UTF-8 字符串显示。普通指针显示地址，Objective-C 对象指针可显示对象。当指针实际指向二进制数据或其他内容时，请修改显示方式。

可变参数函数的模板仅提供固定参数。近似类型会明确标注。浮点寄存器、结构体和跨多个机器字的参数可能需要自定义 Hook 代码。

数据库由独立的 [igf-signatures](https://github.com/ChiChou/igf-signatures) 仓库维护。IGF 固定发行版本并在安装时校验摘要，运行时完全离线查询。源码用户可运行 `npm run fetch:signatures` 安装数据库。
