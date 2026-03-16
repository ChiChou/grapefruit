# Credits & Open Source Attribution

Grapefruit is an open-source project built upon a foundation of original instrumentation and community-driven research. While we developed some original probes and agents, several modules are architected using logic and methodologies derived from the broader developer ecosystem. We'd like to acknowledge the following projects for their foundational contributions to the field.

## Android

* **[jnitrace-engine](https://github.com/chame1eon/jnitrace-engine)** (MIT License)
Our JNI call tracing logic (`agent/src/droid/hooks/jni.ts`) is ported directly from this engine.
* **[checksec.sh](https://github.com/slimm609/checksec)** (BSD License)
The ELF security checks for RELRO, NX, PIE, and Stack Canaries in the checksec module follow this project's approach.

---

## iOS

* **[passionfruit](https://github.com/chaitin/passionfruit)** (MIT License)
The predecessor of this project.
* **[FLEX](https://github.com/FLEXTool/FLEX)** / **[PonyDebugger](https://github.com/square/PonyDebugger)** (Apache 2.0 License)
The methodology for `NSURLSession` traffic logging is inspired by PonyDebugger / FLEX.
* **[@miticollo's gist](https://gist.github.com/miticollo/aa27be66fd6c12fddd9079fa4f1967bf)**
`lsof` implementation (`agent/src/fruity/modules/lsof.ts`) is derived from this gist.
* **[kibty.town blog](https://kibty.town/blog/arc/)**
Firebase and Firestore hooking implementation is derived from this blog post.

## Disclaimer

Grapefruit is an independent project and is not affiliated with, endorsed by, or sponsored by any of the projects or individuals listed above.

All modules, whether original or derived, are provided "as-is" without warranty of any kind. The original authors of the referenced projects are not responsible for any issues, bugs, or security vulnerabilities that may arise within Grapefruit.

All trademarks, service marks, and logos are the property of their respective owners. Their inclusion here is for attribution purposes only and does not imply any official association.
