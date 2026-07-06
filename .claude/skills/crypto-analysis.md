---
name: crypto-analysis
description: Find and analyze all cryptographic operations in an Android APK. Traces key management, identifies weak algorithms, and generates hooks.
---

# Cryptographic Analysis Workflow

Specialized workflow for finding and analyzing all cryptographic operations in an Android APK.

## When to Use

When you need to audit an app's cryptographic implementation: find encryption/decryption code, identify key management, check for weak algorithms.

## Workflow Steps

### Step 1: Run the native crypto scanners

These implement the marker-gate + per-line rule pattern over jadx's parsed model — far
more accurate than grepping for `"AES"`. Each returns `{findings, count, highSeverityCount,
...summaryFlags}`. Run them all, then triage by `highSeverityCount`.

```bash
# Weak ciphers, ECB/implicit-ECB, weak hashes/MACs, hardcoded keys, static IVs, insecure RNG
jadx-ai crypto-scan <apk>

# Broader crypto API misuse (complementary to crypto-scan)
jadx-ai cryptographic-misuse-scan <apk>

# Hardcoded keys/IVs/salts specifically
jadx-ai hardcoded-crypto-scan <apk>

# Unsafe encryption patterns
jadx-ai unsafe-encryption-scan <apk>

# AndroidKeyStore posture: key-no-user-auth, no-StrongBox, randomized-encryption-off
jadx-ai keystore-scan <apk>
jadx-ai insecure-keystore-scan <apk>

# Tokens (JWT/OAuth) stored in plaintext
jadx-ai token-storage-scan <apk>

# Certificate pinning posture (OkHttp/TrustKit/NSC/custom TrustManager)
jadx-ai cert-pinning-scan <apk>
jadx-ai ssl-scan <apk>            # the inverse: trust-all TM/Verifier → MITM

# Native crypto constants in bundled .so (AES S-box, RC4, MD5/SHA-256 init)
jadx-ai native-lib-security <apk>
```

The checklist below maps directly to what these scanners detect automatically — use the
scanners, then manually confirm the findings by decompiling.

### Step 2: Decompile the flagged crypto classes

For each class a scanner flags, pivot to the source:
```bash
jadx-ai decompile -c <crypto-class> <apk>
jadx-ai decompile -c <crypto-class> --with-inners <apk>
jadx-ai class-detail -c <crypto-class> <apk>

# Smali ground truth when the Java looks wrong (e.g. jadx dropped a block)
jadx-ai smali -c <crypto-class> <apk>
```

### Step 3: Trace key management & data flow

```bash
# Every caller of a key/crypto API (method-level, incl. framework APIs)
jadx-ai call-sites -m getSecretKey <apk>
jadx-ai call-sites -m doFinal <apk>

# Where is a hardcoded key literal used?
jadx-ai string-xref -q '<key-bytes-or-string>' <apk>

# Who calls this crypto method? (upstream)
jadx-ai usage -c <crypto-class> -m <crypto-method> -t useIn --depth 3 <apk>

# What does the crypto method use? (downstream)
jadx-ai usage -c <crypto-class> -m <crypto-method> -t used --depth 3 <apk>

jadx-ai graph -t call -c <crypto-class> -m <crypto-method> --depth 5 <apk>
```

### Step 4: Generate dynamic analysis hooks

```bash
# Hook crypto operations at runtime to capture keys/plaintext
jadx-ai hook -t frida -c <crypto-class> -m <crypto-method> <apk>
jadx-ai hook -t frida -c <key-class> -m <key-method> <apk>
```

## Security Findings Checklist

| Check | Risk Level | What to Look For |
|-------|-----------|------------------|
| Hardcoded keys | **CRITICAL** | Byte arrays, string literals used as keys |
| ECB mode | **HIGH** | "AES/ECB/" in transformation string |
| MD5/SHA-1 for passwords | **HIGH** | MessageDigest.getInstance("MD5") |
| DES/3DES | **HIGH** | Weak block ciphers |
| No IV/nonce | **MEDIUM** | CBC without random IV |
| Keys in SharedPreferences | **MEDIUM** | Unencrypted key storage |
| Custom crypto | **MEDIUM** | Non-standard implementations |
| No certificate pinning | **LOW** | TrustManager accepting all certs |
| Static IV | **LOW** | IV hardcoded or derived predictably |

## Report Template

```markdown
# Crypto Analysis Report

## Summary
- Total crypto classes: <count>
- High-risk findings: <count>
- Key management: <AndroidKeyStore / hardcoded / SharedPreferences>

## Findings

### [CRITICAL] Hardcoded AES Key
- **Class**: `com.example.a.b`
- **Key**: Found in static byte array
- **Code**: <snippet>
- **Impact**: Anyone who decompiles the APK can extract the key
- **Recommendation**: Use Android Keystore

### [HIGH] ECB Mode Usage
- **Class**: `com.example.crypto.AESHelper`
- **Transformation**: `AES/ECB/PKCS5Padding`
- **Code**: <snippet>
- **Impact**: Identical plaintext blocks produce identical ciphertext
- **Recommendation**: Use AES/GCM/NoPadding

## Call Graph
<mermaid graph showing crypto call chains>

## Frida Hooks
<generated hook snippets>
```
