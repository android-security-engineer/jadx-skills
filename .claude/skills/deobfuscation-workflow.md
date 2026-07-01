---
name: deobfuscation-workflow
description: Systematically rename obfuscated identifiers in an Android APK to restore readability.
---

# Deobfuscation Workflow

Systematically rename obfuscated identifiers (classes, methods, fields, packages) to restore code readability.

## Workflow Steps

### Step 1: Assess Obfuscation Level

```bash
# Check app info
jadx-ai info <apk>

# Try auto-deobfuscation first
jadx-ai decompile -c <target-class> --deobfuscation <apk>

# List packages to see naming patterns
jadx-ai list -t package <apk>

# List classes to identify obfuscated names
jadx-ai list -t class -p "a" <apk>  # Single-letter package = likely obfuscated
```

**Obfuscation indicators:**
- Packages named `a`, `a.b`, `a.b.c`
- Classes named `a`, `b`, `c`, `C0001`
- Methods named `a()`, `b()`, `c()`
- Fields named `a`, `b`, `c`

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

For systematically renaming by pattern:

```bash
# Find all classes in an obfuscated package
jadx-ai list -t class -p "com.example.a" <apk>

# For each class, decompile → understand → rename
# Use consistent naming conventions:
#   - Activities: XxxActivity
#   - Fragments: XxxFragment  
#   - Services: XxxService
#   - Managers: XxxManager
#   - Adapters: XxxAdapter
#   - Handlers: XxxHandler
#   - Views: XxxView
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
