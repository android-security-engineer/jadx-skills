---
name: jadx-rename
description: Rename classes, methods, fields, or packages in Android APK/DEX files using JADX AI-CLI. Returns structured JSON results.
---

# JADX Rename Skill

Rename classes, methods, fields, or packages in decompiled code to apply meaningful names.

## Usage

1. Identify the target to rename (class, method, field, or package)
2. Run the JADX AI-CLI rename command with the target and new name
3. Present the confirmation result

## Command

```bash
jadx-ai rename -t <type> -n <new-name> [options] <input-file>
```

## Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `<input-file>` | Yes | APK, DEX, JAR, AAR, or class file |
| `-t, --type` | Yes | Target type: `class`, `method`, `field`, `package` |
| `-c, --class` | Conditional | Class full name (required for method/field rename) |
| `-m, --method` | No | Method name to rename (requires --class) |
| `-f, --field` | No | Field name to rename (requires --class) |
| `-p, --package` | No | Package full name to rename |
| `-n, --name` | No | New name (alias) to set. Omit with --remove-alias to revert |
| `--remove-alias` | No | Remove alias and revert to original name |

## Examples

```bash
# Rename a class
jadx-ai rename -t class -c "com.example.a" -n "MainActivity" app.apk

# Rename a method
jadx-ai rename -t method -c "com.example.MainActivity" -m "a" -n "onCreate" app.apk

# Rename a field
jadx-ai rename -t field -c "com.example.MainActivity" -f "b" -n "mTextView" app.apk

# Rename a package
jadx-ai rename -t package -p "com.example.a" -n "com.example.ui" app.apk

# Remove an alias (revert to original)
jadx-ai rename -t class -c "com.example.MainActivity" --remove-alias app.apk
```
