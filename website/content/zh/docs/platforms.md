# 平台功能

## 模式

**App 模式**附加到用户应用，拥有完整功能。

**进程模式**附加到系统进程，依赖目标应用的功能（如 Info.plist、Entitlements、WebViews 等）不可用，保留通用功能（checksec、文件浏览、内存扫描等）。

> 由于移动系统的沙箱和内存限制，部分系统进程可能不支持附加，强行附加会导致进程异常退出。

## iOS

### 安全缓解措施

![安全缓解措施](/mitigations.png)

检查二进制安全标志：PIE、ARC、栈保护器、代码签名和受限权限。

### Info.plist 与 Insights

![Insights](/insights.png)

查看应用的 Info.plist，Insights 面板还会对 ATS 设置、权限和其他配置进行自动化安全分析。

### Entitlements

提取并显示应用的 entitlements。突出显示安全相关的 entitlements，如 keychain 访问组、应用组、关联域和后台模式。

### Assets.car

![Assets.car](/assets.png)

浏览编译后的 asset catalog。查看应用中打包的图片、图标和其他资源。

### WebViews

**iOS (WKWebView / UIWebView):**

![WKWebView](/wkwebview.png)

- 列出所有活动的 WKWebView 实例，含 URL、标题及配置（JS 启用状态、content JS、自动打开窗口、file URL 访问、universal access、content blocker、inspectable）
- UIWebView 支持（用于旧版应用）
- 在 WebView 上下文中执行任意 JavaScript
- 导航到指定 URL
- 启用 WebKit Remote Inspector（iOS 16.4+）

**Android (WebView):**

![Android WebView](/android-webview.png)

- 列出所有活动的 WebView 实例，含 URL、标题及设置（JS、文件访问、内容访问、file:// URL access、universal access、safe browsing、mixed content、database、DOM storage）
- 显示暴露给 Web 内容的注入 JavaScript 接口
- 启用 WebContents 调试
- 在 WebView 上下文中执行任意 JavaScript
- 导航到指定 URL

### JSContext

![JSContext](/jscontext.png)

探索 JavaScriptCore 上下文。在 JS 运行时中执行 JavaScript 表达式并检查应用状态。

### XPC

监控应用与系统服务之间的 XPC（进程间通信）流量。查看消息内容、方向（发送/接收）、连接详情，以及发送消息的调用栈。

### 地理位置模拟

覆盖目标应用的设备 GPS 位置。设置任意坐标来测试位置相关行为。

### 应用扩展

列出随应用打包的所有应用扩展（小组件、分享扩展、通知内容等）。

## Android

### APK 浏览器

浏览应用 APK 文件的内容。提取单个条目（DEX 文件、原生库、资源、assets）用于分析。

### AndroidManifest.xml

![AndroidManifest](/android-manifest.png)

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

![IL2CPP](/ilcpp.png)

分析使用 IL2CPP 提前编译的 Unity 应用。从 IL2CPP 运行时浏览 .NET 元数据、类和方法。
