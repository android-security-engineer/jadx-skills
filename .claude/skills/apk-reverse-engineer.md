---
name: apk-reverse-engineer
description: Structured reverse engineering workflow for Android APK. From entry points to call graphs, deobfuscation to hook generation.
---

# APK Reverse Engineering Workflow

Structured reverse engineering process for understanding how an Android app works, from high-level architecture to individual method behavior.

## When to Use

When you need to understand an Android app's behavior: find key logic, trace data flows, rename obfuscated code, and generate dynamic analysis hooks.

## Workflow Steps

### Phase 1: Reconnaissance

```bash
# Get app overview
jadx-ai info <apk>

# Framework/packer triage — decides downstream tooling
jadx-ai framework-detect <apk>     # Flutter/Unity/Xamarin/.Net/Kotlin? (no getCode, fast)
jadx-ai packer-detect <apk>        # secneo/qihoo/bangcle/DexGuard? (obfuscation-report feeds this)

# Discover entry points
jadx-ai navigate -t entry-points <apk>
jadx-ai navigate -t main-activity <apk>

# Browse package structure
jadx-ai list -t package <apk>

# Class/method/field inventory + DEX-level stats
jadx-ai class-inventory <apk>
jadx-ai dex-stat <apk>

# Read AndroidManifest (or use the manifest scanners in apk-security-audit)
jadx-ai resources --include-resources -t MANIFEST --content <apk>
```

**Goal**: Understand the app's scale, framework, packing, entry points, and high-level architecture. A packed or cross-platform APK changes the plan (deobfuscate first, or reach for blutter/Il2CppDumper).

### Phase 2: Target Identification

```bash
# Search for relevant classes (substring/regex)
jadx-ai search -t class -q "Login" <apk>
jadx-ai search -t class -q "Api" <apk>
jadx-ai search -t method -q "authenticate" <apk>

# Structured type-hierarchy queries (more precise than name search)
jadx-ai find-classes --by super -q "Activity" <apk>          # all Activity subclasses
jadx-ai find-classes --by interface -q "Runnable" <apk>       # all Runnable implementors
jadx-ai find-classes --by annotation -q "JavascriptInterface" <apk>  # JS-bridge classes

# Reverse string lookup — where is this URL/key/magic-string used? (method-level)
jadx-ai string-xref -q "https://api.example.com" <apk>
jadx-ai string-xref -q "Bearer" <apk>

# Find every caller of an API (incl. external framework APIs usage can't reach)
jadx-ai call-sites -m getDeviceId <apk>
jadx-ai call-sites -m loadLibrary <apk>

# Native bridges if JNI is in play
jadx-ai native-bridge-index <apk>      # native methods + @JavascriptInterface
```

**Goal**: Identify classes and methods relevant to your research question. Prefer
`find-classes`/`string-xref`/`call-sites` over `search` when you have a specific target —
they return method-level locations, not just matching source lines.

### Phase 3: Deep Dive

```bash
# Get class details for each target
jadx-ai class-detail -c <target-class> <apk>

# Decompile the target class
jadx-ai decompile -c <target-class> <apk>

# For complex classes, decompile individual methods
jadx-ai decompile -c <target-class> -m <target-method> <apk>

# Smali (Dalvik bytecode) — ground truth when the Java output is suspect
jadx-ai smali -c <target-class> <apk>
jadx-ai smali -c <target-class> -m 'onCreate(Landroid/os/Bundle;)V' <apk>  # single method

# Map source lines to bytecode
jadx-ai line-map -c <target-class> --annotations <apk>
```

**Goal**: Read and understand the target code. Reach for `smali` when jadx's Java looks
wrong (dropped blocks, mis-renamed) — it is the bytecode truth.

### Phase 4: Relationship Mapping

```bash
# Who calls this method?
jadx-ai usage -c <target-class> -m <target-method> <apk>

# What does this method call?
jadx-ai usage -c <target-class> -m <target-method> -t used <apk>

# Deep call chain (3 levels)
jadx-ai usage -c <target-class> -m <target-method> -t used --depth 3 <apk>

# Generate call graph
jadx-ai graph -t call -c <target-class> --depth 5 <apk>

# Generate inheritance graph
jadx-ai graph -t inheritance -c <target-class> <apk>

# Control flow graph for a specific method
jadx-ai cfg -c <target-class> -m <target-method> <apk>
```

**Goal**: Understand how the target code connects to the rest of the app.

### Phase 5: Deobfuscation (if needed)

```bash
# Triage obfuscation: machine-name ratio, reflection density, decrypt-candidate methods, packer sigs
jadx-ai obfuscation-report <apk>
jadx-ai source-quality-report <apk>

# Enable deobfuscation mode
jadx-ai decompile -c <target-class> --deobfuscation <apk>

# Manually rename obfuscated identifiers
jadx-ai rename -t class -c "com.example.a" -n "LoginManager" <apk>
jadx-ai rename -t method -c "com.example.LoginManager" -m "a" -n "verifyPassword" <apk>
jadx-ai rename -t field -c "com.example.LoginManager" -f "b" -n "mPassword" <apk>

# Verify renames by re-decompiling
jadx-ai decompile -c com.example.LoginManager <apk>

# Add code comments for documentation
jadx-ai comment -c com.example.LoginManager <apk>
```

**Goal**: Make the code readable by giving meaningful names to obfuscated identifiers.
`obfuscation-report` tells you whether it's worth the effort and surfaces the static
`String f(...)` decryptor candidates to investigate. See the deobfuscation-workflow skill.

### Phase 6: Dynamic Analysis Preparation

```bash
# Generate Frida hooks
jadx-ai hook -t frida -c <target-class> <apk>
jadx-ai hook -t frida -c <target-class> -m <target-method> <apk>

# Generate Xposed module
jadx-ai hook -t xposed -c <target-class> <apk>

# Anti-root/anti-frida bypass snippets (inventory from tamper-detection-scan)
jadx-ai tamper-detection-scan <apk>      # find the defences first
jadx-ai bypass-hook -t frida <apk>       # emit bypass snippets for them

# Export decompiled code for offline analysis
jadx-ai export -o ./analysis -p <target-package> <apk>
```

**Goal**: Prepare tools for runtime analysis and verification. Run `tamper-detection-scan`
before dynamic work so you know which defences you'll need to bypass.

## Tips for AI Agents

1. **Start broad, then narrow**: Begin with `info` + `navigate`, then narrow to specific classes.
2. **Use `--search-parent`**: When a class has `DONT_GENERATE`, the parent class contains the code.
3. **Use `--deobfuscation`**: Many commercial apps are obfuscated; this helps reveal class/method names.
4. **Trace both directions**: `useIn` (who calls this) and `used` (what this calls) give different perspectives.
5. **Save intermediate findings**: Use `rename` to name discovered classes, `comment` to annotate.
6. **Daemon mode for speed**: If analyzing multiple commands, start the daemon first:
   ```bash
   jadx-ai daemon start <apk> --background
   ```
