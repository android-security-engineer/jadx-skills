---
name: jadx-list
description: List packages, classes, methods, or fields in Android APK/DEX files using JADX AI-CLI. Returns structured JSON.
---

# JADX List Skill

Browse the structure of an Android APK/DEX file by listing packages, classes, methods, or fields.

## Usage

When the user asks to explore, browse, or list the structure of an Android app:

1. Determine what to list (packages, classes, methods, fields)
2. Run the JADX AI-CLI list command
3. Present the structured results

## Command

```bash
jadx-ai list -t <type> [-p <package>] [-c <class>] <input-file>
```

## Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `<input-file>` | Yes | Path to APK, DEX, JAR, AAR file |
| `-t, --type` | No | List type: `packages`, `classes`, `methods`, `fields` (default: classes) |
| `-p, --package` | No | Filter by package name |
| `-c, --class` | No | Class name (required for methods/fields) |

## Examples

```bash
# List all packages
jadx-ai list -t packages app.apk

# List classes in a specific package
jadx-ai list -t classes -p com.example.app app.apk

# List methods of a class
jadx-ai list -t methods -c com.example.app.MainActivity app.apk

# List fields of a class
jadx-ai list -t fields -c com.example.app.MainActivity app.apk
```
