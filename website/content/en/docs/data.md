# Data Inspection

## File Browser

Browse the app's filesystem with a tree view. Download files to your machine, or upload files to the device. Supports both the app sandbox and (on jailbroken/rooted devices) the full filesystem.

## Keychain / KeyStore

**iOS**: Dump all keychain items accessible to the app, including passwords, certificates, and generic items. View access control attributes and protection classes.

**Android**: Inspect the Android KeyStore. List stored keys and certificates with their properties.

## Network Monitoring

**NSURL (iOS)**: Capture NSURLSession requests and responses in real time. View headers, body, and timing. Download request/response data for offline analysis.

![NSURL](/nsurl.webp)

**HTTP (Android)**: Intercept HTTP traffic from OkHttp and other common clients. View requests and responses with headers and body content.

> **Note**: HTTP monitoring is hook-based. See [Known Limitations](/docs/limits#http-monitoring-is-hook-based) for coverage details.

## Crypto Monitor

Intercept cryptographic operations (AES, RSA, HMAC, etc.) in real time. View the algorithm, key material, input data, and output for each operation. Helps identify insecure crypto usage and extract encryption keys.

## Privacy Monitor

Track access to sensitive APIs — location, contacts, photos, camera, microphone, clipboard, and more. See which code paths trigger privacy-sensitive operations.

## Binary Cookies (iOS)

Parse and display the app's binary cookie files. View cookie names, values, domains, expiry dates, and flags (secure, httpOnly).

## UserDefaults (iOS)

![UserDefaults](/userdefaults.webp)

View and modify NSUserDefaults entries for the app. Useful for finding feature flags, cached tokens, and configuration values.

## Open File Descriptors

List all open file descriptors (lsof) for the target process. Shows file paths, socket connections, and pipe endpoints.
