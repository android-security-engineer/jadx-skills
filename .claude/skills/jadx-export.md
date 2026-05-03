---
name: jadx-export
description: Export decompiled Android classes to Java source files using JADX AI-CLI. Supports package and class filtering.
---

# JADX Export Skill

Export decompiled classes from an Android APK/DEX file to Java source files on disk.

## Usage

When the user asks to export, save, or dump decompiled code:

1. Determine the output directory and any filters
2. Run the JADX AI-CLI export command
3. Report the export summary

## Command

```bash
jadx-ai export -o <output-dir> [-p <package>] [-c <class>] [--export-format java|smali] <input-file>
```

## Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `<input-file>` | Yes | Path to APK, DEX, JAR, AAR file |
| `-o, --output` | Yes | Output directory path |
| `-p, --package` | No | Export only classes in this package |
| `-c, --class` | No | Export only this specific class |
| `--export-format` | No | Export format: `java` (default) or `smali` |

## Examples

```bash
# Export all classes
jadx-ai export -o ./output app.apk

# Export only a specific package
jadx-ai export -o ./output -p com.example.app app.apk

# Export a single class
jadx-ai export -o ./output -c com.example.app.MainActivity app.apk

# Export as smali
jadx-ai export -o ./output --export-format smali app.apk
```
