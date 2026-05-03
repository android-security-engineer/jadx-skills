---
name: jadx-line-map
description: Get decompiled-to-source line mapping and code annotations from Android APK using JADX AI-CLI. Maps decompiled line numbers back to original source lines.
---

# JADX Line Map Skill

Get decompiled-to-source line mapping and code position annotations.

## Usage

When the user asks about line number mapping, source line tracing, or code annotations at positions:

1. Run the JADX AI-CLI line-map command
2. Present the structured results

## Command

```bash
jadx-ai line-map -c <class-name> [--annotations] [--usage-map] <input-file>
```

## Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `<input-file>` | Yes | Path to APK, DEX file |
| `-c, --class` | Yes | Full class name |
| `--annotations` | No | Include code annotations (node refs at each position) |
| `--usage-map` | No | Include usage map (position → node mapping) |

## Output Fields

- className: full class name
- lineMap: list of {decompiledLine, sourceLine} mappings
- annotations: (with --annotations) list of {position, type, nodeFullName, nodeType}
- usageMap: (with --usage-map) list of {position, nodeFullName, nodeType}

## Examples

```bash
# Get line mapping
jadx-ai line-map -c com.example.MyClass app.apk

# Get line mapping with annotations
jadx-ai line-map -c com.example.MyClass --annotations app.apk

# Get line mapping with usage map
jadx-ai line-map -c com.example.MyClass --usage-map app.apk
```
