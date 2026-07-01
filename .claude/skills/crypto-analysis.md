---
name: crypto-analysis
description: Find and analyze all cryptographic operations in an Android APK. Traces key management, identifies weak algorithms, and generates hooks.
---

# Cryptographic Analysis Workflow

Specialized workflow for finding and analyzing all cryptographic operations in an Android APK.

## When to Use

When you need to audit an app's cryptographic implementation: find encryption/decryption code, identify key management, check for weak algorithms.

## Workflow Steps

### Step 1: Identify Crypto Primitives

```bash
# Java Crypto API classes
jadx-ai search -t class -q "Cipher" <apk>
jadx-ai search -t class -q "MessageDigest" <apk>
jadx-ai search -t class -q "Mac" <apk>
jadx-ai search -t class -q "Signature" <apk>
jadx-ai search -t class -q "SecretKey" <apk>
jadx-ai search -t class -q "KeyPairGenerator" <apk>
jadx-ai search -t class -q "KeyStore" <apk>

# Algorithm-specific searches
jadx-ai search -t string -q "AES" <apk>
jadx-ai search -t string -q "RSA" <apk>
jadx-ai search -t string -q "DES" <apk>
jadx-ai search -t string -q "MD5" <apk>
jadx-ai search -t string -q "SHA-1" <apk>
jadx-ai search -t string -q "HmacSHA" <apk>
jadx-ai search -t string -q "ECB" <apk>
jadx-ai search -t string -q "CBC" <apk>
jadx-ai search -t string -q "GCM" <apk>

# Method names
jadx-ai search -t method -q "encrypt" <apk>
jadx-ai search -t method -q "decrypt" <apk>
jadx-ai search -t method -q "digest" <apk>
jadx-ai search -t method -q "sign" <apk>
jadx-ai search -t method -q "verify" <apk>
jadx-ai search -t method -q "initCipher" <apk>
jadx-ai search -t method -q "doFinal" <apk>
```

### Step 2: Decompile Crypto Classes

For each crypto class found:
```bash
jadx-ai decompile -c <crypto-class> <apk>

# If class has inners/anonymous classes
jadx-ai decompile -c <crypto-class> --with-inners <apk>

# Get class structure first
jadx-ai class-detail -c <crypto-class> <apk>
```

### Step 3: Trace Key Management

```bash
# How are keys created?
jadx-ai search -t method -q "generateKey" <apk>
jadx-ai search -t method -q "getKey" <apk>
jadx-ai search -t method -q "getSecret" <apk>

# Where are keys stored?
jadx-ai search -t string -q "KeyStore" <apk>
jadx-ai search -t string -q "AndroidKeyStore" <apk>
jadx-ai search -t class -q "SharedPreferences" <apk>

# Are keys hardcoded?
jadx-ai search -t string -q "0x" <apk>
# Look for byte arrays in decompiled code: new byte[] { 0x... }
```

### Step 4: Analyze Call Chains

For each crypto method:
```bash
# Who calls this crypto method? (upstream)
jadx-ai usage -c <crypto-class> -m <crypto-method> -t useIn --depth 3 <apk>

# What does the crypto method use? (downstream)
jadx-ai usage -c <crypto-class> -m <crypto-method> -t used --depth 3 <apk>

# Generate call graph
jadx-ai graph -t call -c <crypto-class> -m <crypto-method> --depth 5 <apk>
```

### Step 5: Check for IV/Nonce Handling

```bash
jadx-ai search -t method -q "IvParameterSpec" <apk>
jadx-ai search -t string -q "GCMParameterSpec" <apk>
jadx-ai search -t method -q "updateAAD" <apk>
```

### Step 6: Generate Dynamic Analysis Hooks

```bash
# Hook crypto operations at runtime
jadx-ai hook -t frida -c <crypto-class> -m <crypto-method> <apk>

# Hook key generation
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
