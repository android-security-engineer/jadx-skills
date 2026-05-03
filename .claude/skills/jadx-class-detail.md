---
name: jadx-class-detail
description: Get detailed class structure from Android APK using JADX AI-CLI. Includes inheritance, inner classes, access flags, full method signatures.
---

# JADX Class Detail Skill

Get detailed class structure information including inheritance, inner classes, access flags, and full method signatures.

## Usage

When the user asks about class structure, inheritance hierarchy, method signatures, or access modifiers:

1. Run the JADX AI-CLI class-detail command
2. Present the structured results

## Command

```bash
jadx-ai class-detail -c <class-name> <input-file>
```

## Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `<input-file>` | Yes | Path to APK, DEX file |
| `-c, --class` | Yes | Full class name |

## Examples

```bash
# Get full class details
jadx-ai class-detail -c com.example.MyClass app.apk

# Get details for an Activity
jadx-ai class-detail -c com.example.app.MainActivity app.apk
```