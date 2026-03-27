# Platform Features

## iOS

### Security Mitigations

Check binary security flags: PIE, ARC, stack canaries, code signing, and restricted entitlements.

### Info.plist & Insights

View the app's Info.plist. The Insights panel also runs automated security analysis on ATS settings, permissions, and other configuration.

### Entitlements

Extract and display the app's entitlements. Key security-relevant items are highlighted — keychain access groups, app groups, associated domains, and background modes.

### Assets.car

Browse the compiled asset catalog. View images, icons, and other assets bundled in the app.

### WebViews

Inspect active WKWebView and UIWebView instances. Debug embedded web content and evaluate JavaScript in the WebView context.

### JSContext

Explore JavaScriptCore contexts. Evaluate JavaScript expressions and inspect the JS runtime of the app.

### XPC

Trace XPC (inter-process communication) messages sent and received by the app. View message content and connection details.

### Geolocation Simulation

Override the device's GPS location for the target app. Set arbitrary coordinates to test location-dependent behavior.

### App Extensions

List all app extensions (widgets, share extensions, notification content, etc.) bundled with the app.

## Android

### APK Browser

Browse the contents of the app's APK file. Extract individual entries (DEX files, native libraries, resources, assets) for analysis.

### AndroidManifest.xml

View the decompiled AndroidManifest with syntax highlighting. Inspect components, permissions, intent filters, and other declarations.

### Components

List all Android components (Activities, Services, Broadcast Receivers, Content Providers) declared by the app with their intent filters and export status.

### Content Providers

Query content providers exposed by the app. Browse data tables, run queries, and test for SQL injection in provider URIs.

### JNI Trace

Trace JNI (Java Native Interface) function calls between Java and native code. Captures method signatures, arguments, and return values.

### Resources

Browse Android app resources (strings, layouts, drawables, etc.) from the APK.

## Cross-Platform

### Flutter Channels

Intercept Flutter platform channel messages between Dart and native code. Supports method channels, event channels, and basic message channels.

### React Native

Inspect the React Native bridge. View bridge messages, evaluate JavaScript in the RN context, and analyze Hermes bytecode.

### IL2CPP (Unity)

Analyze Unity apps that use IL2CPP ahead-of-time compilation. Browse .NET metadata, classes, and methods from the IL2CPP runtime.
