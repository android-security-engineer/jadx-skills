---
name: jadx-package-detail
description: Get detailed package structure from Android APK using JADX AI-CLI. Includes sub-packages, classes, raw names, leaf/root status.
---

# JADX Package Detail Skill

Get detailed package structure information including sub-packages, classes, raw names, and leaf/root status.

## Usage

When the user asks about package structure, sub-packages, or package hierarchy:

1. Run the JADX AI-CLI package-detail command
2. Present the structured results

## Command

```bash
jadx-ai package-detail -p <package-name> <input-file>
```

## Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `<input-file>` | Yes | Path to APK, DEX file |
| `-p, --package` | Yes | Full package name |

## Examples

```bash
# Get package details
jadx-ai package-detail -p com.example.app app.apk

# Get default package details
jadx-ai package-detail -p "" app.apk
```
