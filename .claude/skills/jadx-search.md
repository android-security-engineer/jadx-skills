---
name: jadx-search
description: Search for classes, methods, fields, string constants, or resources in Android APK/DEX files using JADX AI-CLI. Returns structured JSON results.
---

# JADX Search Skill

Search for classes, methods, fields, string constants, or resources in an Android APK/DEX file.

## Usage

When the user asks to find, locate, or search for something in an Android app:

1. Determine the search type (class, method, field, string, resource)
2. Run the JADX AI-CLI search command
3. Present the matching results

## Command

```bash
jadx-ai search -t <type> -q <query> [--exact] [--regex] [-i] [-p <pkg>] [--limit N] <input-file>
```

## Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `<input-file>` | Yes | Path to APK, DEX, JAR, AAR file |
| `-t, --type` | Yes | Search type: `class`, `method`, `field`, `string`, `alias`, `resource` |
| `-q, --query` | Yes | Search query (substring match by default) |
| `--exact` | No | Use exact match instead of substring |
| `--regex` | No | Use regex matching instead of substring |
| `-i, --ignore-case` | No | Case-insensitive matching |
| `-p, --package` | No | Filter results by package name (substring match) |
| `--limit` | No | Max results (default: 50) |
| `--search-parent` | No | Search class or its parent if class has DONT_GENERATE flag |
| `--resource-type` | No | Filter resource search by type (MANIFEST, XML, ARSC, IMG, FONT, JSON, TEXT, HTML, LIB, CODE, APK, ARCHIVE, VIDEOS, SOUNDS) |
| `--max-size` | No | Max resource file size in KB to search (default: 512) |

## Search Types

| Type | Searches In | Result Fields |
|------|------------|---------------|
| `class` | Class full names, simple names, and raw names | fullName, simpleName, packageName, rawName |
| `method` | Method names and full signatures | className, methodName, returnType, fullId |
| `field` | Field names, full signatures, and raw names | className, fieldName, type, rawName |
| `string` | String constants in decompiled code | className, matchingLine |
| `alias` | Class/method aliases (deobfuscated names) | fullName, simpleName, packageName, rawName |
| `resource` | Resource file names and content | name, type, deobfName, matchingLines |

## Examples

```bash
# Search for classes containing "Activity"
jadx-ai search -t class -q Activity app.apk

# Search for a specific method
jadx-ai search -t method -q onClick app.apk

# Search for string constants containing "http"
jadx-ai search -t string -q "http://" app.apk

# Exact class name match
jadx-ai search -t class -q com.example.MainActivity --exact app.apk

# Regex search for onCreate methods
jadx-ai search -t method -q "onCreate.*View" --regex app.apk

# Case-insensitive class search
jadx-ai search -t class -q "activity" -i app.apk

# Search within a specific package
jadx-ai search -t class -q "handler" -p "com.example.network" app.apk

# Search resource content
jadx-ai search -t resource -q "android.permission" --resource-type MANIFEST app.apk
```
