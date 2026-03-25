---
name: audit
description: >-
  Autonomous mobile security audit aligned with OWASP MASTG v2.
  Performs checklist-driven analysis across MASVS categories:
  storage, crypto, network, platform, code, resilience, privacy.
  Exports structured markdown report with MASTG test references.
---

# Mobile Security Audit Skill

You are performing an autonomous security audit of a mobile application using igf (Grapefruit) dynamic instrumentation, aligned with OWASP MASTG v2 (Mobile Application Security Testing Guide).

## Prerequisites

The igf server must be running (`bun src/index.ts` or `igf`). A device must be connected with the target app running.

## Session Setup

1. Run `igf device list` to find connected devices
2. If user didn't specify a device, use the only one or ask
3. Confirm platform (`droid` or `fruity`) and bundle ID

Store as shell variables:

```sh
DEVICE="<device_id>"
PLATFORM="<droid|fruity>"
BUNDLE="<bundle_id>"
SESSION="-d $DEVICE --platform $PLATFORM -b $BUNDLE"
```

## How to Execute

Use `igf` CLI via bash. The `/igf` skill documents all commands.

**Rules:**
- Ask user before starting hooks (`hook start`, `crypto start`)
- Ask user before accessing paths outside app data directory
- If a command fails, note the error and move on
- Collect actual output as evidence for each finding
- Reference MASTG test IDs in findings where applicable

---

## Audit Checklist (OWASP MASTG v2 aligned)

Work through sections in order. Non-intrusive first (1-4, 6), hooks later (5, 7, 8).

Platform: [A] = Android, [I] = iOS, [*] = both.

### 1. MASVS-STORAGE — Data Storage & Privacy

**Collect app info and filesystem roots:**
```sh
igf agent app info $SESSION
igf agent fs roots $SESSION
```

**1.1 Logging** [*] (MASWE-0001)
- [A] MASTG-TEST-0231: Check for references to logging APIs in manifest/code
- [A] MASTG-TEST-0203: Runtime use of logging APIs — `igf log syslog $DEVICE $BUNDLE`
- [I] MASTG-TEST-0297: Insertion of sensitive data into logs
- [I] MASTG-TEST-0296: Sensitive data exposure through insecure logging — `igf log syslog $DEVICE $BUNDLE`
- Flag: tokens, passwords, PII in log output (HIGH)

**1.2 Backup Exposure** [*] (MASWE-0004)
- [A] MASTG-TEST-0262: Check `android:allowBackup` in manifest — `igf agent app manifest $SESSION`
- [A] MASTG-TEST-0216: Sensitive data not excluded from backup
- [I] MASTG-TEST-0215: Sensitive data not marked for backup exclusion
- [I] MASTG-TEST-0298: Runtime monitoring of files eligible for backup

**1.3 Unencrypted Data in Private Storage** [*] (MASWE-0006)
- [A] MASTG-TEST-0207: Runtime storage of unencrypted data in app sandbox
- [A] MASTG-TEST-0287: Sensitive data via SharedPreferences — `igf agent fs ls <data_dir>/shared_prefs $SESSION` then `igf agent fs cat <file> $SESSION`
- [A] MASTG-TEST-0304: Sensitive data via SQLite — `igf agent sqlite tables <path> $SESSION` then `igf agent sqlite dump <path> <table> $SESSION`
- [A] MASTG-TEST-0305: Sensitive data via DataStore
- [A] MASTG-TEST-0306: Sensitive data via Room DB
- [I] MASTG-TEST-0299: Data protection classes for files
- [I] MASTG-TEST-0300/0301: Unencrypted data in private storage — `igf agent ios userdefaults $SESSION`
- [I] MASTG-TEST-0302: Sensitive data unencrypted in private storage files
- Flag: plaintext credentials, tokens, PII in databases or preferences (HIGH)

**1.4 External/Shared Storage** [*] (MASWE-0007)
- [A] MASTG-TEST-0200: Files written to external storage
- [A] MASTG-TEST-0201: Runtime use of external storage APIs
- [A] MASTG-TEST-0202: References to external storage APIs/permissions
- [I] MASTG-TEST-0303: Unencrypted data in shared storage
- Browse: `igf agent fs ls <data_dir> $SESSION`

**1.5 Keychain/Keystore** [*]
- [A] `igf agent android keystore $SESSION` — check key algorithms, purposes
- [A] `igf agent android keystore-info <alias> $SESSION` — detailed attributes
- [I] `igf agent ios keychain $SESSION` — check accessibility levels
- [I] `igf agent ios cookies $SESSION` — session cookies without secure/httpOnly
- Flag: `kSecAttrAccessibleAlways` (HIGH), weak key algorithms

### 2. MASVS-CRYPTO — Cryptography

**2.1 Weak/Broken Algorithms** [*] (MASWE-0020)
- [A] MASTG-TEST-0221: Broken symmetric encryption algorithms
- [A] MASTG-TEST-0232: Broken symmetric encryption modes (ECB)
- [A] MASTG-TEST-0312: Explicit security provider usage
- [I] MASTG-TEST-0210: Broken symmetric encryption algorithms
- [I] MASTG-TEST-0211: Broken hashing algorithms (MD5, SHA1 for security)
- [I] MASTG-TEST-0317: Broken symmetric encryption modes
- Flag: DES, 3DES, RC4, ECB mode (HIGH), MD5/SHA1 for signatures

**2.2 Hardcoded Keys** [*] (MASWE-0014)
- [A] MASTG-TEST-0212: Hardcoded cryptographic keys in code
- [I] MASTG-TEST-0213: Hardcoded cryptographic keys in code
- [I] MASTG-TEST-0214: Hardcoded cryptographic keys in files
- Scan: `igf agent symbol strings <main_module> $SESSION`
- Look for: base64 key-length strings, hex patterns, `-----BEGIN.*KEY-----`

**2.3 Insufficient Key Sizes** [*] (MASWE-0009)
- [A] MASTG-TEST-0208: Insufficient key sizes
- [I] MASTG-TEST-0209: Insufficient key sizes
- Flag: <128-bit symmetric, <2048-bit RSA (HIGH)

**2.4 IV Reuse** [A] (MASWE-0022)
- [A] MASTG-TEST-0309: References to reused IVs
- [A] MASTG-TEST-0310: Runtime use of reused IVs
- Flag: all-zero IVs, static IVs (HIGH)

**2.5 Key Reuse** [*] (MASWE-0012)
- [A] MASTG-TEST-0307/0308: Asymmetric key pairs used for multiple purposes

**2.6 Insecure Random** [*] (MASWE-0027)
- [A] MASTG-TEST-0204/0205: Insecure random / non-random sources
- [I] MASTG-TEST-0311: Insecure random API usage

**Runtime crypto monitoring (ask user first):**
```sh
igf agent crypto start cipher $SESSION    # Android
igf agent crypto start cccrypt $SESSION   # iOS
# wait for app interaction...
igf log crypto $DEVICE $BUNDLE --limit 100
igf agent crypto stop cipher $SESSION
```

### 3. MASVS-NETWORK — Network Communication

**3.1 Cleartext Traffic** [*] (MASWE-0050)
- [A] MASTG-TEST-0233: Hardcoded HTTP URLs
- [A] MASTG-TEST-0235: Android configurations allowing cleartext
- [A] MASTG-TEST-0237: Cross-platform framework cleartext config
- [A] MASTG-TEST-0238: Runtime cleartext traffic
- [A] MASTG-TEST-0239: Low-level socket APIs for custom HTTP
- [I] MASTG-TEST-0321: Hardcoded HTTP URLs
- [I] MASTG-TEST-0322: ATS configurations allowing cleartext — check `NSAllowsArbitraryLoads` in app info
- [I] MASTG-TEST-0323: Low-level networking APIs for cleartext
- Check manifest: `igf agent app manifest $SESSION` — look for `usesCleartextTraffic=true`
- Flag: plaintext HTTP (HIGH), disabled ATS (HIGH)

**3.2 Insecure TLS** [*] (MASWE-0050)
- [A] MASTG-TEST-0217: Insecure TLS protocols allowed in code
- MASTG-TEST-0218: Insecure TLS in network traffic
- [A] MASTG-TEST-0295: GMS security provider not updated
- Flag: TLS 1.0/1.1 (HIGH), SSLv3 (CRITICAL)

**3.3 Certificate Validation** [*] (MASWE-0052)
- [A] MASTG-TEST-0234: Missing hostname verification with SSLSockets
- [A] MASTG-TEST-0282: Unsafe custom trust evaluation
- [A] MASTG-TEST-0283: Incorrect hostname verification
- [A] MASTG-TEST-0284: Incorrect SSL error handling in WebViews
- [A] MASTG-TEST-0285: Outdated version trusting user CAs
- [A] MASTG-TEST-0286: Network security config trusting user CAs

**3.4 Certificate Pinning** [*] (MASWE-0047)
- [A] MASTG-TEST-0242: Missing pinning in network security config
- [A] MASTG-TEST-0243: Expired certificate pins
- MASTG-TEST-0244: Missing pinning in network traffic
- Flag: no pinning (MEDIUM for L2)

**Runtime HTTP monitoring (ask user first):**
```sh
igf agent hook start http $SESSION        # Android
igf agent hook start sslpinning $SESSION  # Android pinning bypass
# wait for app interaction...
igf history http $DEVICE $BUNDLE --limit 100   # Android
igf history nsurl $DEVICE $BUNDLE --limit 100  # iOS
igf agent hook stop http $SESSION
```
Flag: plaintext requests, API keys in headers/URLs, sensitive data in transit

### 4. MASVS-PLATFORM — Platform Interaction

**4.1 WebView Security** [A] (MASWE-0069)
- [A] MASTG-TEST-0250/0251: Content provider access in WebViews
- [A] MASTG-TEST-0252/0253: Local file access in WebViews
- [A] MASTG-TEST-0227: Debugging enabled for WebViews (MASWE-0067)
- [A] MASTG-TEST-0320: WebViews not cleaning up sensitive data (MASWE-0118)

**4.2 Exported Components** [A]
```sh
igf agent android activities $SESSION
igf agent android services $SESSION
igf agent android receivers $SESSION
igf agent android providers $SESSION
```
Flag: exported without permission protection (INFO-MEDIUM), content providers queryable (test with `igf agent android provider-query <uri> $SESSION`)

**4.3 Sensitive UI Data Exposure** [*] (MASWE-0053)
- [A] MASTG-TEST-0258: Keyboard caching attributes
- [A] MASTG-TEST-0316: Auth data in text input fields
- [I] MASTG-TEST-0276-0280: Pasteboard security (general pasteboard, clearing, expiry, local-only)
- [I] MASTG-TEST-0313/0314: Keyboard caching prevention

**4.4 Screenshot/Screen Capture Prevention** [*] (MASWE-0055)
- [A] MASTG-TEST-0289: Sensitive content in screenshots during backgrounding
- [A] MASTG-TEST-0291-0294: Screen capture prevention APIs
- [I] MASTG-TEST-0290: Sensitive content in screenshots during backgrounding

**4.5 Notification Data** [A] (MASWE-0054)
- [A] MASTG-TEST-0315: Sensitive data exposed via notifications

**4.6 Deep Links / URL Schemes** [I]
- [I] `igf agent app urls $SESSION` — check for custom schemes accepting external input

### 5. MASVS-CODE — Code Quality

**5.1 Binary Protections** [*] (MASWE-0116)
```sh
igf agent checksec main $SESSION
```
- [A] MASTG-TEST-0222: PIE not enabled
- [A] MASTG-TEST-0223: Stack canaries not enabled
- [I] MASTG-TEST-0228: PIE not enabled
- [I] MASTG-TEST-0229: Stack canaries not enabled
- [I] MASTG-TEST-0230: ARC not enabled
- Flag: missing PIE (HIGH), missing canaries (MEDIUM), missing ARC (HIGH on iOS)

**5.2 Dependencies** [*] (MASWE-0076)
- [A] MASTG-TEST-0272: Dependencies with known vulnerabilities
- [I] MASTG-TEST-0273: Dependencies with known vulnerabilities
- `igf agent symbol modules $SESSION` — identify third-party libraries

**5.3 Debugging Symbols** [*] (MASWE-0093)
- [A] MASTG-TEST-0288: Debugging symbols in native binaries
- [I] MASTG-TEST-0219: Testing for debugging symbols

**5.4 Platform Version** [A] (MASWE-0077)
- [A] MASTG-TEST-0245: Platform version API references
- Check: `targetSdkVersion` < 33 (MEDIUM)

### 6. MASVS-RESILIENCE — Reverse Engineering & Tampering

**6.1 Debuggable** [*] (MASWE-0067)
- [A] MASTG-TEST-0226: `android:debuggable=true` in manifest — `igf agent app manifest $SESSION`
- [I] MASTG-TEST-0261: `get-task-allow` entitlement — `igf agent app entitlements $SESSION`
- Flag: debuggable in production (HIGH)

**6.2 Code Signing** [*] (MASWE-0104)
- [A] MASTG-TEST-0224: Insecure signature version
- [A] MASTG-TEST-0225: Insecure signature key size
- [I] MASTG-TEST-0220: Outdated code signature format

**6.3 Root/Jailbreak Detection** [*] (MASWE-0097)
- [A] MASTG-TEST-0324/0325: Root detection mechanisms
- [I] MASTG-TEST-0240/0241: Jailbreak detection
- `igf agent class list $SESSION` — search for root/jailbreak detection classes

**6.4 Device Lock** [*] (MASWE-0008)
- [A] MASTG-TEST-0247/0249: Secure screen lock detection
- [I] MASTG-TEST-0246/0248: Secure screen lock detection

**6.5 StrictMode** [A] (MASWE-0094)
- [A] MASTG-TEST-0263-0265: StrictMode violations/APIs

**6.6 Obfuscation Indicators** [*]
- `igf agent class list $SESSION` — short/randomized names = ProGuard/R8
- `igf agent symbol modules $SESSION` — stripped symbols = obfuscation

### 7. MASVS-PRIVACY — User Privacy

**7.1 Dangerous Permissions** [A] (MASWE-0117)
- [A] MASTG-TEST-0254: Dangerous app permissions — extract from manifest
- [A] MASTG-TEST-0255: Permission requests not minimized
- [A] MASTG-TEST-0256: Missing permission rationale
- [A] MASTG-TEST-0257: Not resetting unused permissions
- Flag: >= 8 dangerous permissions (MEDIUM)

**7.2 SDK Data Handling** [*] (MASWE-0112)
- [A] MASTG-TEST-0318/0319: SDK APIs handling sensitive user data
- [I] MASTG-TEST-0281: Undeclared known tracking domains

**7.3 PII in Network Traffic** [A] (MASWE-0108)
- [A] MASTG-TEST-0206: Undeclared PII in network traffic capture

**Runtime privacy monitoring (ask user first):**
```sh
igf agent hook start privacy $SESSION
# wait for app interaction...
igf history privacy $DEVICE $BUNDLE --limit 100
igf agent hook stop privacy $SESSION
```
Categorize: microphone, camera, photos, sensors, bluetooth, wifi, location, health

### 8. Hardcoded Secrets (cross-cutting)

```sh
igf agent symbol modules $SESSION           # find main module
igf agent symbol strings <main_module> $SESSION
```

Search for:
- API keys: `sk_`, `pk_`, `api_`, `key_`, `token_`, `AIza`, `AKIA`, `ghp_`, `glpat-`
- Private keys: `-----BEGIN.*PRIVATE KEY-----`
- URLs with credentials: `://.*:.*@`
- AWS/GCP/Azure patterns
- Firebase config
- Hardcoded IPs and internal hostnames

Also check:
- [A] SharedPreferences XML files for credential-like keys
- [I] `igf agent ios userdefaults $SESSION` for credential-like keys

---

## Cleanup

Stop all active hooks:
```sh
igf agent hook status $SESSION
igf agent hook stop <group> $SESSION   # for each active group
igf agent crypto stop <group> $SESSION
```

## Open Files / Network

```sh
igf agent lsof $SESSION
```
Flag unexpected network connections.

---

## Report Format

Write to file the user specifies (default: `audit-report.md`).

```markdown
# Security Audit Report: {bundle}

| Field | Value |
|-------|-------|
| **Date** | {YYYY-MM-DD} |
| **Platform** | {Android/iOS} |
| **Device** | {device} |
| **Bundle** | {bundle} |
| **Standard** | OWASP MASTG v2 |

## Executive Summary

| Severity | Count |
|----------|-------|
| Critical | N |
| High | N |
| Medium | N |
| Info | N |
| Positive | N |

> **Risk Assessment:** {one sentence}

## Findings

### MASVS-STORAGE

#### [!] {Finding Title}

**Severity:** HIGH | **MASTG:** MASTG-TEST-XXXX | **MASWE:** MASWE-XXXX

{Description}

**Evidence:**
```
{actual igf command output}
```

**Recommendation:** {fix}

### MASVS-CRYPTO
### MASVS-NETWORK
### MASVS-PLATFORM
### MASVS-CODE
### MASVS-RESILIENCE
### MASVS-PRIVACY

## Positive Findings

- [+] **{title}** — {description}

## Recommendations Summary

1. **[CRITICAL]** {rec}
2. **[HIGH]** {rec}
...
```

## Severity Guide

- **CRITICAL**: Immediate exploitation risk (hardcoded credentials, SQL injection in exported provider)
- **HIGH**: Significant weakness (debuggable, disabled ATS, plaintext credentials, weak crypto, missing PIE)
- **MEDIUM**: Notable concern (excessive permissions, missing pinning, legacy storage)
- **INFO**: Worth noting (exported components, missing network security config)
- **OK**: Security control properly implemented
