---
name: jadx-decompile
description: Decompile Android APK/DEX classes to Java source code using JADX AI-CLI. Returns structured JSON with source code.
---

# JADX Decompile Skill

Decompile a specific class or method from an Android APK/DEX file.

## Usage

When the user asks to decompile, view source code, or reverse engineer an Android class:

1. Identify the target APK/DEX file path and class name
2. Run the JADX AI-CLI decompile command
3. Parse and present the JSON result

## Command

```bash
jadx-ai decompile -c <class-name> [-m <method-name>] [--with-smali] [--line-map] <input-file>
```

Or using the built distribution:

```bash
jadx-ai decompile -c <class-name> [-m <method-name>] [--with-smali] [--line-map] <input-file>
```

## Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `<input-file>` | Yes | Path to APK, DEX, JAR, AAR, or class file |
| `-c, --class` | Yes | Full class name (e.g. `com.example.MyClass`) |
| `-m, --method` | No | Method name to decompile specifically |
| `--with-smali` | No | Include smali/disassembly output |
| `--line-map` | No | Include source line mapping (decompiled line → original source line) |

## Output Format

```json
{
  "success": true,
  "data": {
    "className": "com.example.MyClass",
    "sourceCode": "package com.example;\n\npublic class MyClass { ... }",
    "smali": "...",
    "methods": [
      {
        "methodName": "onCreate",
        "returnType": "void",
        "sourceCode": "..."
      }
    ]
  }
}
```

## Error Handling

- `ClassNotFound`: Class name not found, try `jadx-search` first
- `AmbiguousClass`: Multiple matches, use full qualified name
- `MethodNotFound`: Method not found in the specified class

## Examples

```bash
# Decompile a full class
jadx-ai decompile -c com.example.app.MainActivity app.apk

# Decompile a specific method
jadx-ai decompile -c com.example.app.MainActivity -m onCreate app.apk

# Include smali output
jadx-ai decompile -c com.example.app.MainActivity --with-smali app.apk
```
