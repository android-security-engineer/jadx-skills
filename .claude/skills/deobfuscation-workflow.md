---
name: deobfuscation-workflow
description: Systematically rename obfuscated identifiers in an Android APK to restore readability.
---

# Deobfuscation Workflow

Systematically rename obfuscated identifiers (classes, methods, fields, packages) to restore code readability.

## Workflow Steps

### Step 1: Assess Obfuscation Level

Start with the native triage scanners — they quantify the obfuscation so you know whether a
manual rename pass is worth it, and surface the string-decryptor candidates to attack first.

```bash
# Machine-name ratio, reflection density, static String-decrypt candidates, packer signatures
jadx-ai obfuscation-report <apk>

# Broader readability metrics: synthetic bridge %, control-flow flattening hints, source quality
jadx-ai source-quality-report <apk>

# Packer detection — a packed APK must be unpacked/dumped before renaming means anything
jadx-ai packer-detect <apk>

# Check app info
jadx-ai info <apk>

# Try auto-deobfuscation first
jadx-ai decompile -c <target-class> --deobfuscation <apk>

# List classes to identify obfuscated names
jadx-ai list -t class -p "a" <apk>  # Single-letter package = likely obfuscated
```

**Obfuscation indicators** (`obfuscation-report` computes these automatically):
- Packages named `a`, `a.b`, `a.b.c`
- Classes named `a`, `b`, `c`, `C0001`
- Methods named `a()`, `b()`, `c()`
- Fields named `a`, `b`, `c`
- High reflection density + a static `String f(String)` / `byte[] g(...)` decryptor
  (the report flags these as decrypt candidates — they gate most string-level analysis)

**Decision:** if `packer-detect` reports a packer, unpack/dump first (the dex you see is a
stub). If `obfuscation-report` shows a low machine-name ratio, the app is largely unobfuscated
and you can skip the manual pass. Otherwise proceed.

### Step 2: Enable Auto-Deobfuscation

```bash
# Auto-deobfuscation with jadx's built-in engine
jadx-ai info --deobfuscation <apk>

# With custom min/max name length
jadx-ai info --deobfuscation --deobf-min-length 3 --deobf-max-length 40 <apk>

# With whitelist (don't rename these packages)
jadx-ai info --deobfuscation --deobf-whitelist "android.*,androidx.*,kotlin.*" <apk>
```

### Step 3: Manual Rename Strategy

For classes that auto-deobfuscation can't handle:

```bash
# 1. Decompile the class to understand its purpose
jadx-ai decompile -c "com.example.a" <apk>

# 2. Check what it extends/implements
jadx-ai class-detail -c "com.example.a" <apk>

# 3. Check usage to understand role
jadx-ai usage -c "com.example.a" <apk>

# 4. Rename based on understanding
jadx-ai rename -t class -c "com.example.a" -n "LoginActivity" <apk>

# 5. Rename methods based on behavior
jadx-ai rename -t method -c "com.example.LoginActivity" -m "a" -n "validateCredentials" <apk>

# 6. Rename fields based on usage
jadx-ai rename -t field -c "com.example.LoginActivity" -f "b" -n "mPassword" <apk>
```

### Step 4: Batch Rename Pattern

For systematically renaming by pattern. Type-hierarchy queries beat name listing here —
even when a class is named `a`, its supertype/interface tells you what it *is*, so you can
name it correctly without reading the code:

```bash
# Group obfuscated classes by what they extend/implement — instant naming hints
jadx-ai find-classes --by super -q "Activity" <apk>       # → *Activity
jadx-ai find-classes --by super -q "Fragment" <apk>       # → *Fragment
jadx-ai find-classes --by super -q "Service" <apk>        # → *Service
jadx-ai find-classes --by super -q "BroadcastReceiver" <apk>  # → *Receiver
jadx-ai find-classes --by super -q "RecyclerView.Adapter" <apk>  # → *Adapter
jadx-ai find-classes --by interface -q "Runnable" <apk>
jadx-ai find-classes --by annotation -q "JavascriptInterface" <apk>  # JS bridges

# Find all classes in an obfuscated package (fallback when supertype is generic)
jadx-ai list -t class -p "com.example.a" <apk>

# For each class, decompile → understand → rename
# Use consistent naming conventions:
#   - Activities: XxxActivity      - Managers: XxxManager
#   - Fragments: XxxFragment       - Adapters: XxxAdapter
#   - Services: XxxService         - Handlers: XxxHandler
#   - Receivers: XxxReceiver       - Views: XxxView
```

### Step 5: Verify & Export

```bash
# Re-decompile to verify renames
jadx-ai decompile -c <renamed-class> <apk>

# Export fully renamed code
jadx-ai export -o ./deobfuscated-output --save-all <apk>

# Save renames mapping for future sessions
jadx-ai export -o ./output --generated-renames-mapping-file ./renames.txt <apk>
```

### Step 6: Apply Saved Mappings (Future Sessions)

```bash
# Load previously saved renames
jadx-ai info --user-renames-mappings-path ./renames.txt --user-renames-mappings-mode READ_AND_APPLY <apk>
```

## Naming Convention Guide for AI Agents

When renaming obfuscated code, follow Android/Java conventions:

| Pattern | Convention | Example |
|---------|-----------|---------|
| Activity class | `<Purpose>Activity` | `LoginActivity` |
| Fragment class | `<Purpose>Fragment` | `SettingsFragment` |
| Service class | `<Purpose>Service` | `SyncService` |
| BroadcastReceiver | `<Purpose>Receiver` | `BootReceiver` |
| Adapter class | `<Purpose>Adapter` | `ListAdapter` |
| ViewHolder | `<Purpose>ViewHolder` | `ItemViewHolder` |
| Listener/Callback | `On<Purpose>Listener` | `OnItemClickListener` |
| Manager class | `<Purpose>Manager` | `DownloadManager` |
| Helper/Util class | `<Purpose>Helper` / `<Purpose>Util` | `FileHelper` |
| Model/POJO | `<Purpose>` | `UserInfo` |
| Interface | `I<Purpose>` or `<Purpose>able` | `IListener`, `Clickable` |
| Boolean field | `is/m/has<purpose>` | `isLoggedIn`, `mHasPendingUpdate` |
| Member field | `m<purpose>` | `mContext`, `mAdapter` |
| Static field | `s<purpose>` | `sInstance` |
| Constant | `UPPER_SNAKE_CASE` | `MAX_RETRY_COUNT` |
