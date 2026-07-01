---
name: network-analysis
description: Find all network endpoints, API keys, and network security issues in an Android APK.
---

# Network Security Analysis Workflow

Find all network communication, hardcoded secrets, and network security configuration issues.

## Workflow Steps

### Step 1: Discover Network Endpoints

```bash
# Find HTTP/HTTPS URLs
jadx-ai search -t string -q "http://" <apk>
jadx-ai search -t string -q "https://" <apk>

# Find API base URLs
jadx-ai search -t string -q "api." <apk>
jadx-ai search -t string -q "v1/" <apk>
jadx-ai search -t string -q "v2/" <apk>

# Find WebSocket endpoints
jadx-ai search -t string -q "ws://" <apk>
jadx-ai search -t string -q "wss://" <apk>
```

### Step 2: Identify Networking Libraries

```bash
# OkHttp
jadx-ai search -t class -q "OkHttpClient" <apk>
jadx-ai search -t class -q "Interceptor" <apk>

# Retrofit
jadx-ai search -t class -q "Retrofit" <apk>
jadx-ai search -t method -q "create" <apk>

# Volley
jadx-ai search -t class -q "RequestQueue" <apk>

# HttpURLConnection
jadx-ai search -t class -q "HttpURLConnection" <apk>

# WebView (potential XSS)
jadx-ai search -t class -q "WebView" <apk>
jadx-ai search -t method -q "addJavascriptInterface" <apk>
jadx-ai search -t method -q "setJavaScriptEnabled" <apk>
```

### Step 3: Find Hardcoded Secrets

```bash
# API keys and tokens
jadx-ai search -t string -q "api_key" <apk>
jadx-ai search -t string -q "apikey" <apk>
jadx-ai search -t string -q "secret_key" <apk>
jadx-ai search -t string -q "access_token" <apk>
jadx-ai search -t string -q "Bearer" <apk>
jadx-ai search -t string -q "Authorization" <apk>

# Firebase / Google
jadx-ai search -t string -q "AIza" <apk>    # Google API key prefix
jadx-ai search -t string -q "firebase" <apk>

# AWS
jadx-ai search -t string -q "AKIA" <apk>    # AWS access key prefix
jadx-ai search -t string -q "aws_secret" <apk>
```

### Step 4: Check SSL/TLS Configuration

```bash
# Custom TrustManagers (often insecure)
jadx-ai search -t class -q "X509TrustManager" <apk>
jadx-ai search -t method -q "checkServerTrusted" <apk>
jadx-ai search -t method -q "checkClientTrusted" <apk>

# HostnameVerifier bypass
jadx-ai search -t method -q "verify" <apk>

# Network security config
jadx-ai resources --include-resources --content <apk> | grep -A5 "network-security-config"
```

### Step 5: Trace Network Call Chains

```bash
# Decompile networking classes
jadx-ai decompile -c <network-class> <apk>

# Trace from network call back to business logic
jadx-ai usage -c <network-class> -m <request-method> -t useIn --depth 3 <apk>

# Trace from entry point to network call
jadx-ai usage -c <entry-class> -m <action-method> -t used --depth 5 <apk>
```

### Step 6: Generate Hooks for Traffic Interception

```bash
# Hook OkHttp interceptor
jadx-ai hook -t frida -c <okhttp-class> -m <intercept-method> <apk>

# Hook URL connection
jadx-ai hook -t frida -c <url-class> -m <openConnection> <apk>
```
