---
name: apk-security-audit
description: Comprehensive security audit of an Android APK. Identifies attack surface, crypto usage, network endpoints, permission risks, and generates hook snippets.
---

# APK Security Audit Workflow

Comprehensive security audit combining multiple jadx-ai commands into a structured analysis pipeline.

## When to Use

When you need a full security assessment of an Android APK: attack surface analysis, crypto usage, network security, permission risks, and hook generation.

## Prerequisites

- APK file loaded in jadx-ai (daemon mode recommended for speed)
- jadx-ai CLI available in PATH

## Workflow Steps

### Step 1: APK Overview & Signature Verification
```bash
jadx-ai info <apk>
jadx-ai signature <apk>
```

**What to look for:**
- Total class/method count → estimate app complexity
- APK signature validity → check for repackaging
- V1/V2/V3 signing schemes used
- Certificate details → identify the signer

### Step 2: Entry Point Discovery
```bash
jadx-ai navigate -t entry-points <apk>
jadx-ai navigate -t main-activity <apk>
jadx-ai navigate -t application <apk>
```

**What to look for:**
- Main launch activity
- Application class (initialization code)
- Exported activities/services/receivers (attack surface)
- Deep link handlers

### Step 3: Permission & Manifest Analysis
```bash
jadx-ai resources --include-resources -t MANIFEST --content <apk>
```

**What to look for:**
- Dangerous permissions: CAMERA, LOCATION, READ_PHONE_STATE, etc.
- Exported components without permission protection
- Custom permissions with protectionLevel="normal"
- Backup enabled (android:allowBackup="true")
- Debuggable flag (android:debuggable="true")
- Network security config

### Step 4: Network Security Analysis
```bash
jadx-ai search -t string -q "http://" <apk>
jadx-ai search -t string -q "https://" <apk>
jadx-ai search -t class -q "OkHttp" <apk>
jadx-ai search -t class -q "Retrofit" <apk>
jadx-ai search -t class -q "WebView" <apk>
jadx-ai search -t string -q "api_key" <apk>
jadx-ai search -t string -q "secret" <apk>
```

**What to look for:**
- HTTP (non-HTTPS) URLs → cleartext traffic
- Hardcoded API keys/secrets/tokens
- WebView usage (potential XSS if JavaScript enabled)
- Custom certificate trust managers

### Step 5: Cryptographic Analysis
```bash
jadx-ai search -t class -q "Cipher" <apk>
jadx-ai search -t method -q "encrypt" <apk>
jadx-ai search -t method -q "decrypt" <apk>
jadx-ai search -t method -q "MessageDigest" <apk>
jadx-ai search -t string -q "AES" <apk>
jadx-ai search -t string -q "RSA" <apk>
jadx-ai search -t string -q "MD5" <apk>
jadx-ai search -t string -q "SHA-1" <apk>
```

**For each crypto class found:**
```bash
jadx-ai decompile -c <crypto-class> <apk>
jadx-ai usage -c <crypto-class> -t useIn <apk>
```

**What to look for:**
- Hardcoded encryption keys/IVs
- Weak algorithms (DES, MD5, SHA-1 used for passwords)
- ECB mode usage
- Custom crypto implementations (often insecure)
- Key stored in code vs. Android Keystore

### Step 6: Sensitive Data Analysis
```bash
jadx-ai search -t string -q "password" <apk>
jadx-ai search -t string -q "token" <apk>
jadx-ai search -t string -q "credit" <apk>
jadx-ai search -t method -q "SharedPreferences" <apk>
jadx-ai search -t class -q "SQLiteDatabase" <apk>
jadx-ai search -t method -q "getContentResolver" <apk>
```

**What to look for:**
- Hardcoded credentials
- Sensitive data in SharedPreferences (unencrypted)
- SQL injection risks (string concatenation in queries)
- Content providers without proper permissions

### Step 7: Dynamic Analysis Hook Generation
```bash
# Generate Frida hooks for key methods
jadx-ai hook -t frida -c <target-class> <apk>
jadx-ai hook -t frida -c <target-class> -m <target-method> <apk>
```

### Step 8: Call Graph Analysis (Deep Traces)
```bash
# Trace from entry points
jadx-ai usage -c <entry-class> -m <entry-method> -t used --depth 3 <apk>

# Trace to sensitive sinks
jadx-ai usage -c <crypto-class> -m <sensitive-method> -t useIn --depth 3 <apk>

# Generate call graph visualization
jadx-ai graph -t call -c <target-class> --depth 5 --format mermaid <apk>
```

## Report Template

```markdown
# Security Audit Report: <APP_NAME>

## 1. App Overview
- Package: <package-name>
- Version: <version>
- Signing: <valid/invalid>, schemes: <V1/V2/V3>
- Certificate: <subject>, valid until <date>
- Classes: <count>, Methods: <count>

## 2. Attack Surface
- Exported activities: <list>
- Exported services: <list>
- Exported receivers: <list>
- Deep links: <list>
- Debuggable: <yes/no>
- Backup allowed: <yes/no>

## 3. Network Security
- Cleartext traffic: <list of HTTP URLs>
- Hardcoded secrets: <list>
- Custom trust managers: <list>
- WebView with JS enabled: <list>

## 4. Cryptographic Issues
- Weak algorithms: <list>
- Hardcoded keys: <list>
- ECB mode: <list>
- Custom crypto: <list>

## 5. Data Storage
- Unencrypted SharedPreferences: <list>
- SQL injection risks: <list>
- Content provider exposure: <list>

## 6. Recommendations
1. <recommendation>
2. <recommendation>
```
