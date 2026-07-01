---
name: apk-security-audit
description: Comprehensive security audit of an Android APK. Runs the native MASVS-aligned scanners for attack surface, crypto, network, storage, IPC, and privacy, then generates hook snippets for dynamic follow-up.
---

# APK Security Audit Workflow

Comprehensive security audit driven by jadx-ai's **native scanner commands**. Rather than
manually grepping with `search`, this workflow runs the purpose-built scanners that each
implement a marker-gate + per-line rule list over jadx's parsed model — far more accurate
than string search and far faster than spinning up MobSF/QARK.

## When to Use

When you need a full security assessment of an Android APK: attack surface, crypto, network,
storage, IPC, privacy, and anti-tamper posture — with hook snippets for dynamic follow-up.

## Prerequisites

- APK file path (a real `.apk` with an `AndroidManifest.xml` for the manifest-based scanners)
- `jadx-ai` CLI available in PATH
- Daemon mode (`jadx-ai daemon start`) recommended — the decompiler loads once and every
  scanner reuses the in-memory model instead of reloading per command.

## Workflow

The audit runs in phases. Each phase is a single scanner that returns structured JSON
(`{success, data:{findings, count, highSeverityCount, ...summaryFlags}}`). Triage by
`highSeverityCount` first; read `findings[].detail` for the why.

### Phase 1 — Overview, signature & framework triage
```bash
jadx-ai info <apk>                      # class/method/field counts → app complexity
jadx-ai apk-signature <apk>             # v1/v2/v3/v4 signing schemes + cert SHA-256
jadx-ai framework-detect <apk>          # Flutter/Unity/Xamarin/.Net? decides downstream tooling
jadx-ai packer-detect <apk>             # secneo/qihoo/bangcle/DexGuard? flags packed APKs
jadx-ai dex-stat <apk>                  # multidex heuristic, method density
```
**Triage:** a packed or cross-platform APK changes the plan (deobfuscation first, or reach
for blutter/Il2CppDumper instead of pure jadx).

### Phase 2 — Manifest, permissions & exported surface
```bash
jadx-ai manifest-security-audit <apk>   # debuggable/allowBackup/cleartextTraffic + exported-guard cross-ref
jadx-ai custom-permission-audit <apk>   # <permission> protectionLevel hex parse + self-uses-permission
jadx-ai permission-risk-map <apk>       # declared perms → dangerous-API table → callsites
jadx-ai dangerous-api-map <apk>         # @RequiresPermission API callers (signature-precise)
jadx-ai shared-uid-audit <apk>          # sharedUserId / android.uid.* system UID
jadx-ai network-security-config <apk>   # NSC: cleartextPermitted, user-CA trust (MITM), pin-set
jadx-ai deep-link-audit <apk>           # VIEW intent-filter schemes/hosts, browsable http w/o autoVerify
jadx-ai task-hijacking-scan <apk>       # StrandHogg: taskAffinity/launchMode per activity
jadx-ai backup-scan <apk>              # allowBackup + fullBackupContent rules
```

### Phase 3 — IPC & component vulnerabilities
```bash
jadx-ai exported-provider-scan <apk>    # ContentProvider SQLi/path-traversal (provider-aware)
jadx-ai content-provider-scan <apk>     # grantUriPermission, world-read URIs
jadx-ai intent-scan <apk>              # mutable PendingIntent (CVE-class), sticky/dynamic broadcasts
jadx-ai intent-redirection-scan <apk>   # CWE-927 confused-deputy (getParcelableExtra→startActivity)
jadx-ai pending-intent-scan <apk>       # FLAG_MUTABLE vs FLAG_IMMUTABLE classification
jadx-ai unsafe-export-scan <apk>        # exported components w/o permission guard
jadx-ai broadcast-scan <apk>           # sticky broadcasts, dynamic receiver registration
jadx-ai fragment-injection-scan <apk>   # Fragment injection via extras
jadx-ai deeplink-scan <apk>            # deep-link handler reachability
jadx-ai insecure-deeplink-handler-scan <apk>
```

### Phase 4 — Crypto, keys & secrets
```bash
jadx-ai secrets-scan <apk>              # AIza/AKIA/Stripe/GitHub/JWT/PEM + Shannon entropy
jadx-ai crypto-scan <apk>              # weak ciphers, ECB, weak hashes/MACs, static IVs, insecure RNG
jadx-ai cryptographic-misuse-scan <apk> # broader crypto API misuse
jadx-ai hardcoded-crypto-scan <apk>     # hardcoded keys/IVs/salts
jadx-ai unsafe-encryption-scan <apk>
jadx-ai keystore-scan <apk>            # AndroidKeyStore: key-no-user-auth, no-StrongBox, rand-enc-off
jadx-ai insecure-keystore-scan <apk>
jadx-ai token-storage-scan <apk>       # JWT/OAuth tokens in plaintext storage
jadx-ai cert-pinning-scan <apk>        # pinning posture inventory (OkHttp/TrustKit/NSC/custom TM)
jadx-ai firebase-scan <apk>            # DB URLs → openDbCheckUrls (/.json unauth check endpoints)
jadx-ai google-services-config <apk>
```

### Phase 5 — Network & transport
```bash
jadx-ai ioc-extract --decode-defang <apk>   # URLs/IPs/domains/endpoints; recovers hxxp/[.] defanged forms
jadx-ai api-endpoint-extract <apk>     # Retrofit annotations + OkHttp .url() → endpoint list
jadx-ai network-traffic-scan <apk>     # cleartext HTTP, hosts, custom TrustManager
jadx-ai ssl-scan <apk>                 # trust-all TrustManager/Verifier → MITM (inverse of cert-pinning)
jadx-ai webview-scan <apk>            # setAllowUniversalAccess, JS bridge, MIXED_CONTENT, debug
jadx-ai webview-url-scan <apk>        # loaded URLs (cleartext, sensitive)
```

### Phase 6 — Injection & code-execution sinks
```bash
jadx-ai sql-injection-scan <apk>       # SQLite rawQuery/execSQL with string concat (parameterized = safe)
jadx-ai command-injection-scan <apk>   # Runtime.exec / ProcessBuilder with concat/shell/su
jadx-ai path-traversal-scan <apk>      # Zip Slip + intent-extra→File (canonical-guard aware)
jadx-ai xxe-scan <apk>                 # XML parser factories w/o secure-processing
jadx-ai serialization-scan <apk>       # readObject, Jackson default-typing, getParcelableExtra
jadx-ai subprocess-scan <apk>
jadx-ai insecure-file-io-scan <apk>
jadx-ai dynamic-loading-scan <apk>     # DexClassLoader/load from external source
jadx-ai command-injection-scan <apk>
```

### Phase 7 — Data storage & privacy
```bash
jadx-ai storage-scan <apk>             # MODE_WORLD_READABLE, external storage, plaintext prefs/SQLite
jadx-ai privacy-scan <apk>             # data collection inventory (IMEI/ANDROID_ID/ad-id/installed-apps)
jadx-ai location-scan <apk>           # requestLocationUpdates, GPS/Fused, mock-detection
jadx-ai sim-info-scan <apk>           # ICCID/IMSI/IMEI/phone-number reads, SubscriptionManager
jadx-ai account-scan <apk>            # AccountManager tokens/accounts/Authenticator
jadx-ai bluetooth-scan <apk>          # adapter/gatt/socket, BLE scan, inbound server socket
jadx-ai clipboard-scan <apk>          # clipboard monitor/write/read
jadx-ai screen-capture-scan <apk>
jadx-ai screenshot-leak-scan <apk>
jadx-ai log-info-leak-scan <apk>       # sensitive data in Log.*/printStackTrace
jadx-ai logging-scan <apk>
jadx-ai data-residue-scan <apk>
```

### Phase 8 — Resilience & anti-tamper posture (dual-use)
```bash
jadx-ai tamper-detection-scan <apk>    # root/emulator/debugger/frida-xposed/attestation defences
jadx-ai runtime-integrity-scan <apk>
jadx-ai debug-artifact-scan <apk>      # Stetho/Flipper/LeakCanary/StrictMode residue in release
jadx-ai tapjacking-scan <apk>         # overlay windows, FLAG_SECURE, touch-obscure protection
jadx-ai accessibility-scan <apk>       # AccessibilityService screen-scrape/keylogger/ui-automation
jadx-ai notification-listener-scan <apk>  # OTP/2FA theft via NotificationListenerService
jadx-ai sms-scan <apk>                # SMS intercept/send/abort-broadcast
jadx-ai otp-interception-scan <apk>
jadx-ai biometric-scan <apk>          # biometric w/o crypto binding (Frida-bypassable)
jadx-ai local-auth-bypass-scan <apk>
jadx-ai sensor-scan <apk>
jadx-ai device-admin-scan <apk>
jadx-ai vpn-service-scan <apk>
jadx-ai nfc-scan <apk>
jadx-ai alarm-wakelock-scan <apk>      # Doze-bypass alarms, PARTIAL_WAKE_LOCK, BOOT_COMPLETED
```

### Phase 9 — Native & JNI
```bash
jadx-ai native-bridge-index <apk>      # native methods + WebView @JavascriptInterface bridges
jadx-ai native-libs <apk>             # bundled .so: strings, JNI symbols, IOC/anti-debug markers
jadx-ai native-lib-security <apk>     # ELF checksec (NX/PIE/RELRO/canary) + crypto constants
jadx-ai il2cpp-metadata-scan <apk>     # Unity IL2CPP global-metadata.dat
jadx-ai flutter-analysis <apk>        # Flutter libapp.so / Dart snapshot
```

### Phase 10 — Deep-dive a finding
When a scanner flags a class/line, pivot to the source and trace the data flow:
```bash
jadx-ai decompile -c <class> <apk>          # the Java
jadx-ai smali -c <class> <apk>              # ground-truth bytecode when Java is suspect
jadx-ai smali -c <class> -m '<shortId>' <apk>  # single method's smali
jadx-ai string-xref -q '<literal>' <apk>    # where is this URL/key/string used?
jadx-ai call-sites -m '<apiName>' <apk>     # every caller of an API (incl. framework APIs)
jadx-ai find-classes --by super -q '<Super>' <apk>   # all subclasses
jadx-ai find-classes --by interface -q '<Iface>' <apk>
jadx-ai find-classes --by annotation -q '<Ann>' <apk>
jadx-ai usage -c <class> -m <method> -t useIn --depth 3 <apk>   # who calls this?
jadx-ai graph -t call -c <class> --depth 5 --format mermaid <apk>
```

### Phase 11 — Dynamic follow-up hooks
```bash
jadx-ai hook -t frida -c <target-class> <apk>
jadx-ai hook -t frida -c <target-class> -m <target-method> <apk>
jadx-ai bypass-hook -t frida <apk>          # anti-root/anti-frida bypass snippets
# Then drive the script at runtime:
jadx-ai frida run-script --pkg <package> --script <script.js>
```

## Triage rules

1. **`highSeverityCount > 0`** → stop and read those findings first. They are CVE-class
   (mutable PendingIntent, intent redirection, trust-all TM, hardcoded keys, SQLi with
   concat, external dex load, etc.).
2. **Summary booleans** (`usesBluetooth`, `tracksLocation`, `readsSimIdentifiers`,
   `touchesAuthTokens`, `acceptsConnections`, `checksMockLocation`…) describe the app's
   capability posture in one field — compare against the manifest's declared permissions
   to spot over-privileged or under-declared behaviour.
3. **`pinsCertificates=false` / `appLevelMitigated`** style absence flags — can't be pinned
   to a line; treat as a posture gap to confirm manually.
4. **Dual-use scanners** (tamper-detection, cert-pinning, mock-location) inventory *defences*;
   for an RE engagement these are your bypass-target list, not vulnerabilities.

## Report template

```markdown
# Security Audit Report: <APP_NAME>

## 1. Overview
- Package/Version/Signing (schemes + cert SHA-256)/Framework/Packer/Class count

## 2. Attack Surface (Phase 2-3)
- Exported components w/o guard; deep links; task-hijack susceptibility; mutable PendingIntents;
  intent redirection; provider SQLi/traversal; shared UID.

## 3. Crypto & Secrets (Phase 4)
- Hardcoded keys/secrets; weak ciphers/ECB/MD5; Keystore protection gaps; pinning posture;
  Firebase open-DB check URLs.

## 4. Network (Phase 5)
- Cleartext traffic; trust-all TM (MITM); WebView config; extracted endpoints/IOCs.

## 5. Injection & Code Execution (Phase 6)
- SQLi; command injection; path traversal/Zip Slip; XXE; unsafe deserialization; dynamic load.

## 6. Storage & Privacy (Phase 7)
- World-readable storage; plaintext prefs/SQLite; PII collected (location/SIM/accounts/bt…).

## 7. Resilience Posture (Phase 8)
- Anti-root/anti-frida/anti-debug present? biometric crypto-bound? debug residue?

## 8. Native (Phase 9)
- JNI bridges; .so checksec; crypto constants; IL2CPP/Flutter.

## 9. Recommendations
1. <recommendation per high-severity finding>
```
