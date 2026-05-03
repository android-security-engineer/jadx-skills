---
name: jadx-search
description: Search for classes, methods, fields, or string constants in Android APK/DEX files using JADX AI-CLI. Returns structured JSON results.
---

# JADX Search Skill

Search for classes, methods, fields, or string constants in an Android APK/DEX file.

## Usage

When the user asks to find, locate, or search for something in an Android app:

1. Determine the search type (class, method, field, string)
2. Run the JADX AI-CLI search command
3. Present the matching results

## Command

```bash
jadx-ai search -t <type> -q <query> [--exact] [--limit N] <input-file>
```

## Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `<input-file>` | Yes | Path to APK, DEX, JAR, AAR file |
| `-t, --type` | Yes | Search type: `class`, `method`, `field`, `string`, `alias` |
| `-q, --query` | Yes | Search query (substring match by default) |
| `--exact` | No | Use exact match instead of substring |
| `--limit` | No | Max results (default: 50) |

## Search Types

| Type | Searches In | Result Fields |
|------|------------|---------------|
| `class` | Class full names and simple names | fullName, simpleName, packageName |
| `method` | Method names | className, methodName |
| `field` | Field names | className, fieldName |
| `string` | String constants in source code | className, matchingLine |

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
```
