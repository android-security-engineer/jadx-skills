---
name: jadx-resources
description: List and read embedded resource files from Android APK using JADX AI-CLI. Access AndroidManifest.xml, layouts, strings, images, etc.
---

# JADX Resources Skill

List and read embedded resource files from an Android APK.

## Usage

When the user asks about Android resources, manifests, layouts, or embedded files:

1. Run the JADX AI-CLI resources command
2. Present the structured results

## Command

```bash
jadx-ai resources [--include-resources] [-t <type>] [-n <name>] [--content] <input-file>
```

## Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `<input-file>` | Yes | Path to APK file |
| `--include-resources` | Yes | Must include this flag to load resources |
| `-t, --type` | No | Filter by type: MANIFEST, XML, ARSC, IMG, FONT, JSON, TEXT, HTML, LIB |
| `-n, --name` | No | Filter by name (substring match) |
| `--content` | No | Include text content of resources |

## Examples

```bash
# List all resources
jadx-ai resources --include-resources app.apk

# Get AndroidManifest
jadx-ai resources --include-resources -t MANIFEST app.apk

# Search for layout XMLs
jadx-ai resources --include-resources -t XML -n "layout" app.apk

# Read string resources with content
jadx-ai resources --include-resources -t ARSC --content app.apk
```
