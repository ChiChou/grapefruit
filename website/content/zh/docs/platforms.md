# 平台功能

## iOS

### 安全缓解措施

检查二进制安全标志：PIE、ARC、栈保护器、代码签名和受限权限。

### Info.plist 与 Insights

查看应用的 Info.plist，Insights 面板还会对 ATS 设置、权限和其他配置进行自动化安全分析。

### Entitlements

提取并显示应用的 entitlements。突出显示安全相关的 entitlements，如 keychain 访问组、应用组、关联域和后台模式。

### Assets.car

浏览编译后的 asset catalog。查看应用中打包的图片、图标和其他资源。

### WebViews

检查活动的 WKWebView 和 UIWebView 实例。调试嵌入式 Web 内容并在 WebView 上下文中执行 JavaScript。

### JSContext

探索 JavaScriptCore 上下文。在 JS 运行时中执行 JavaScript 表达式并检查应用状态。

### XPC

追踪应用发送和接收的 XPC（进程间通信）消息。查看消息内容和连接详情。

### 地理位置模拟

覆盖目标应用的设备 GPS 位置。设置任意坐标来测试位置相关行为。

### 应用扩展

列出随应用打包的所有应用扩展（小组件、分享扩展、通知内容等）。

## Android

### APK 浏览器

浏览应用 APK 文件的内容。提取单个条目（DEX 文件、原生库、资源、assets）用于分析。

### AndroidManifest.xml

以语法高亮查看反编译后的 AndroidManifest。检查组件、权限、intent filters 和其他声明。

### 组件

列出应用声明的所有 Android 组件（Activity、Service、Broadcast Receiver、Content Provider）及其 intent filters 和导出状态。

### Content Providers

查询应用暴露的 Content Providers。浏览数据表、运行查询，并测试 provider URI 中的 SQL 注入。

### JNI 追踪

追踪 Java 和原生代码之间的 JNI（Java Native Interface）函数调用。捕获方法签名、参数和返回值。

### 资源

浏览从 APK 提取的 Android 应用资源（字符串、布局、可绘制资源等）。

## 跨平台

### Flutter Channels

拦截 Dart 和原生代码之间的 Flutter 平台通道消息。支持 Method Channel、Event Channel 和基本 Message Channel。

### React Native

检查 React Native bridge。查看 bridge 消息、在 RN 上下文中执行 JavaScript，并分析 Hermes 字节码。

### IL2CPP（Unity）

分析使用 IL2CPP 提前编译的 Unity 应用。从 IL2CPP 运行时浏览 .NET 元数据、类和方法。
