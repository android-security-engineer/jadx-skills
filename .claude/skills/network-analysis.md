---
name: network-analysis
description: Find all network endpoints, API keys, and network security issues in an Android APK.
---

# Network Security Analysis Workflow

Find all network communication, hardcoded secrets, and network security configuration
issues — driven by jadx-ai's **native scanner commands**. Each scanner implements a
marker-gate + per-line rule list over jadx's parsed model, far more accurate than grepping
string literals with `search`. Every scanner returns
`{success, data:{findings, count, highSeverityCount, ...summaryFlags}}`; triage by
`highSeverityCount` first.

## Workflow Steps

### Step 1: Discover Network Endpoints & IOCs

```bash
# URLs / IPs / domains / endpoints in one pass; --decode-defang recovers
# hxxp://, [.] , [dot] , [at] , [:] obfuscated (defanged) indicators
jadx-ai ioc-extract --decode-defang <apk>

# Retrofit annotations (@GET/@POST/...) + OkHttp .url() → structured endpoint list
jadx-ai api-endpoint-extract <apk>

# Cleartext HTTP hosts, ws://, custom TrustManager usage in one sweep
jadx-ai network-traffic-scan <apk>
```

`ioc-extract` replaces the old manual `search -t string -q "http://"` sweep and additionally
recovers defanged threat-intel indicators. `api-endpoint-extract` gives method-level
locations for each REST endpoint instead of raw matching lines.

### Step 2: Identify Networking Libraries & WebViews

```bash
# WebView attack surface: setJavaScriptEnabled, addJavascriptInterface bridge,
# setAllowUniversalAccessFromFileURLs, MIXED_CONTENT, setWebContentsDebuggingEnabled
jadx-ai webview-scan <apk>
jadx-ai webview-url-scan <apk>          # URLs actually loaded (cleartext / sensitive)

# Native JS bridges + JNI (attack surface for injected JS → Java)
jadx-ai native-bridge-index <apk>       # @JavascriptInterface + native methods

# For library classes themselves, structured type queries beat name search:
jadx-ai find-classes --by interface -q "Interceptor" <apk>   # OkHttp interceptors
jadx-ai find-classes --by super -q "WebViewClient" <apk>     # custom WebViewClients
```

### Step 3: Find Hardcoded Secrets

```bash
# Curated regex set (Google AIza, AWS AKIA, Slack xox*, Stripe, GitHub, JWT eyJ,
# PEM headers) + Shannon-entropy filter over string literals AND text resources
jadx-ai secrets-scan <apk>

# Firebase DB URLs → openable /.json unauth check endpoints
jadx-ai firebase-scan <apk>
jadx-ai google-services-config <apk>    # google-services.json / values secrets

# Tokens (JWT/OAuth) persisted in plaintext storage
jadx-ai token-storage-scan <apk>
```

`secrets-scan` replaces the whole manual `search -t string -q "AIza"/"AKIA"/"api_key"`
battery — it is signature- and entropy-driven, redacts the match, and reports confidence.

### Step 4: Check SSL/TLS Configuration

```bash
# Trust-all TrustManager / permissive HostnameVerifier → MITM (the vulnerability)
jadx-ai ssl-scan <apk>

# Certificate-pinning posture inventory (OkHttp CertificatePinner / TrustKit / NSC pin-set
# / custom TrustManager) — the inverse of ssl-scan; absence of pinning is the gap
jadx-ai cert-pinning-scan <apk>

# Network Security Config: cleartextTrafficPermitted, user-CA trust anchors (MITM), pin-set
jadx-ai network-security-config <apk>
```

`ssl-scan` + `cert-pinning-scan` together replace the manual `search` for
`X509TrustManager`/`checkServerTrusted`/`verify` and the NSC resource grep — with
line-level findings and posture summary flags (`pinsCertificates`, `trustsUserCa`, …).

### Step 5: Trace Network Call Chains

```bash
# Every caller of a networking API (incl. framework APIs usage can't reach)
jadx-ai call-sites -m execute <apk>          # OkHttp Call.execute / Volley
jadx-ai call-sites -m openConnection <apk>   # HttpURLConnection

# Where is a discovered base URL / endpoint literal used? (method-level)
jadx-ai string-xref -q "https://api.example.com" <apk>

# Decompile a flagged networking class, then trace both directions
jadx-ai decompile -c <network-class> <apk>
jadx-ai usage -c <network-class> -m <request-method> -t useIn --depth 3 <apk>  # who calls it
jadx-ai usage -c <network-class> -m <request-method> -t used  --depth 3 <apk>  # what it calls
```

### Step 6: Generate Hooks for Traffic Interception

```bash
# Hook OkHttp interceptor / URL connection to capture plaintext traffic
jadx-ai hook -t frida -c <okhttp-class> -m <intercept-method> <apk>
jadx-ai hook -t frida -c <url-class> -m openConnection <apk>

# If pinning/anti-MITM is present (per cert-pinning-scan / ssl-scan), emit bypass snippets
jadx-ai bypass-hook -t frida <apk>
```

## Findings Triage

| Scanner | High-severity signal | Meaning |
|---------|---------------------|---------|
| `ssl-scan` | trust-all `checkServerTrusted{}` / `verify(){return true}` | MITM-able, no transport security |
| `network-traffic-scan` | cleartext `http://` to app hosts | credentials/data in the clear |
| `secrets-scan` | live API key / private key literal | key extractable from APK |
| `firebase-scan` | open `/.json` DB endpoint | unauth DB read/write |
| `webview-scan` | JS bridge + `setAllowUniversalAccess` | JS → native RCE surface |
| `cert-pinning-scan` | `pinsCertificates=false` | posture gap (no pinning) — confirm intent |

Compare `network-traffic-scan` / `webview-scan` capability flags against the manifest's
`usesCleartextTraffic` and `network-security-config` output to spot contradictions
(e.g. NSC forbids cleartext but code opens `http://`).
