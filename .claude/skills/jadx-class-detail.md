---
name: jadx-class-detail
description: Get detailed class structure from Android APK using JADX AI-CLI. Includes inheritance, inner classes, access flags, full method signatures, dependencies, codeParent, isNoCode.
---

# JADX Class Detail Skill

Get detailed class structure information including inheritance, inner classes, access flags, full method signatures, dependencies, and code parent.

## Usage

When the user asks about class structure, inheritance hierarchy, method signatures, access modifiers, or dependencies:

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

## Output Fields

- fullName, simpleName, packageName, rawName, isInner
- accessFlags (raw int), accessStr (e.g. "public final")
- declaringClass, topParentClass
- innerClasses, inlinedClasses (list of full names)
- methods: name, returnType, arguments, isConstructor, accessFlags, accessStr
- fields: name, type, accessFlags, accessStr
- dependencies (list of class full names this class depends on)
- totalDepsCount
- codeParent (class that contains this class's code, differs for anonymous/inlined)
- originalTopParentClass
- isNoCode (true if class marked DONT_GENERATE)

## Examples

```bash
# Get full class details
jadx-ai class-detail -c com.example.MyClass app.apk

# Get details for an Activity
jadx-ai class-detail -c com.example.app.MainActivity app.apk
```