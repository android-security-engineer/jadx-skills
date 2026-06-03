---
name: jadx-script
description: Run JavaScript scripts to operate on the JADX decompiler instance for Android APK/DEX files. Returns structured JSON results.
---

# JADX Script Skill

Run custom scripts that have direct access to the JadxDecompiler instance for advanced analysis or automation.

## Usage

1. Write a JavaScript file that uses the `decompiler` and `inputFile` variables
2. Run the JADX AI-CLI script command with the script file
3. Present the script output

## Command

```bash
jadx-ai script [options] <script-file> <input-file>
```

## Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `<script-file>` | Yes | Path to the JavaScript (.js) file |
| `<input-file>` | Yes | APK, DEX, JAR, AAR, or class file |
| `--engine` | No | Script engine: `js` (default) |

## Available Variables

| Variable | Type | Description |
|----------|------|-------------|
| `decompiler` | `JadxDecompiler` | The loaded decompiler instance with full API access |
| `inputFile` | `File` | The input file being analyzed |

## Examples

```bash
# Run a custom analysis script
jadx-ai script analyze.js app.apk

# Run with explicit engine
jadx-ai script --engine js custom.js app.apk
```
