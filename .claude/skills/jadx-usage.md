---
name: jadx-usage
description: Query usage relationships and call graph from Android APK using JADX AI-CLI. Find who calls a method, who references a class, etc.
---

# JADX Usage Skill

Query usage relationships (call graph, references) from decompiled Android code.

## Usage

When the user asks about call graphs, references, who uses what, or code relationships:

1. Run the JADX AI-CLI usage command
2. Present the structured results

## Command

```bash
jadx-ai usage -c <class> [-m <method>] [-f <field>] [-t <type>] <input-file>
```

## Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `<input-file>` | Yes | Path to APK, DEX file |
| `-c, --class` | Yes | Class name to query |
| `-m, --method` | No | Method name (requires --class) |
| `-f, --field` | No | Field name (requires --class) |
| `-t, --type` | No | Query type: useIn (who uses this) or used (what this uses) |

## Examples

```bash
# Who uses this class?
jadx-ai usage -c com.example.MyClass app.apk

# Who calls this method?
jadx-ai usage -c com.example.MyClass -m doSomething app.apk

# What methods does this method call?
jadx-ai usage -c com.example.MyClass -m doSomething -t used app.apk

# Who references this field?
jadx-ai usage -c com.example.MyClass -f myField app.apk
```
