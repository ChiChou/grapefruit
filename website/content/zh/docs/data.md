# 数据审查

## 文件浏览器

以树形视图浏览应用的文件系统。下载文件到本地，或上传文件到设备。支持沙盒内文件系统，以及（已越狱/root 设备上的）完整文件系统。

## Keychain / KeyStore

**iOS**：转储应用可访问的所有 Keychain 条目，包括密码、证书和通用项目。查看访问控制属性和保护类。

**Android**：检查 Android KeyStore。列出存储的密钥和证书及其属性。

## 网络监控

**NSURL（iOS）**：实时捕获 NSURLSession 请求和响应。查看请求头、正文和时间。下载请求/响应数据用于离线分析。

![NSURL](/nsurl.webp)

**HTTP（Android）**：拦截来自 OkHttp 等常见客户端的 HTTP 流量。查看带请求头和正文的请求和响应。

> **注意**：HTTP 监控基于 Hook 实现。详见[已知限制](/docs/limits#http-monitoring-is-hook-based)。

## 加密监控

实时拦截加密操作（AES、RSA、HMAC 等）。查看每个操作的算法、密钥材料、输入数据和输出。有助于识别不当的加密操作并提取密钥。

## 隐私监控

跟踪对敏感 API 的访问——位置、联系人、照片、相机、麦克风、剪贴板等。查看哪些代码路径触发隐私敏感操作。

## Binary Cookies（iOS）

解析并显示应用的二进制 Cookie 文件。查看 Cookie 名称、值、域、过期日期和标志（secure、httpOnly）。

## UserDefaults（iOS）

![UserDefaults](/userdefaults.webp)

查看和修改应用的 NSUserDefaults 条目。可用于查找功能开关、缓存的 token 和配置值。

## 打开的文件描述符

列出目标进程的所有打开文件描述符（lsof）。显示文件路径、套接字连接和管道端点。
