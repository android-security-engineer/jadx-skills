---
name: jadx-reload
description: Reload, recompile, or unload class code in Android APK/DEX files using JADX AI-CLI. Returns structured JSON results.
---

# JADX Reload Skill

Reload or unload decompiled class code, or refresh code data for updated analysis.

## Usage

1. Identify the class to reload or decide to reload all classes
2. Run the JADX AI-CLI reload command
3. Present the confirmation result

## Command

```bash
jadx-ai reload [options] <input-file>
```

## Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `<input-file>` | Yes | APK, DEX, JAR, AAR, or class file |
| `-c, --class` | No | Class full name to reload/unload |
| `-t, --type` | No | Action: `reload` (recompile class), `unload` (free code), `codedata` (refresh all code data). Default: `reload` |
| `--all` | No | Apply action to all classes |

## Examples

```bash
# Reload a specific class (recompile)
jadx-ai reload -c "com.example.MainActivity" app.apk

# Unload a specific class (free memory)
jadx-ai reload -c "com.example.MainActivity" -t unload app.apk

# Refresh all code data
jadx-ai reload --all -t codedata app.apk

# Reload all classes
jadx-ai reload --all app.apk
```
