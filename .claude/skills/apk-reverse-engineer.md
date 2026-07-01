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

# Discover entry points
jadx-ai navigate -t entry-points <apk>

# Browse package structure
jadx-ai list -t package <apk>

# Read AndroidManifest
jadx-ai resources --include-resources -t MANIFEST --content <apk>
```

**Goal**: Understand the app's scale, entry points, and high-level architecture.

### Phase 2: Target Identification

```bash
# Search for relevant classes
jadx-ai search -t class -q "Login" <apk>
jadx-ai search -t class -q "Api" <apk>
jadx-ai search -t class -q "Network" <apk>
jadx-ai search -t class -q "Encrypt" <apk>
jadx-ai search -t class -q "Config" <apk>

# Search for specific behaviors
jadx-ai search -t method -q "onCreate" <apk>
jadx-ai search -t method -q "onClick" <apk>
jadx-ai search -t method -q "verify" <apk>
jadx-ai search -t method -q "authenticate" <apk>

# Search for hardcoded strings
jadx-ai search -t string -q "https://api." <apk>
jadx-ai search -t string -q "Bearer" <apk>
```

**Goal**: Identify classes and methods relevant to your research question.

### Phase 3: Deep Dive

```bash
# Get class details for each target
jadx-ai class-detail -c <target-class> <apk>

# Decompile the target class
jadx-ai decompile -c <target-class> <apk>

# For complex classes, decompile individual methods
jadx-ai decompile -c <target-class> -m <target-method> <apk>

# Get smali/disassembly for native understanding
jadx-ai decompile -c <target-class> --with-smali <apk>

# Map source lines to bytecode
jadx-ai line-map -c <target-class> --annotations <apk>
```

**Goal**: Read and understand the target code.

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

### Phase 6: Dynamic Analysis Preparation

```bash
# Generate Frida hooks
jadx-ai hook -t frida -c <target-class> <apk>
jadx-ai hook -t frida -c <target-class> -m <target-method> <apk>

# Generate Xposed module
jadx-ai hook -t xposed -c <target-class> <apk>

# Export decompiled code for offline analysis
jadx-ai export -o ./analysis -p <target-package> <apk>
```

**Goal**: Prepare tools for runtime analysis and verification.

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
