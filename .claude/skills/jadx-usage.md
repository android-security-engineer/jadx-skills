---
name: jadx-usage
description: Query code reference relationships (call graph, cross-references) in Android APK/DEX files using JADX AI-CLI. Supports useIn (who references this) and used (what this references) queries for classes, methods, and fields. Supports recursive depth exploration.
---

# JADX Usage Skill

Query code reference relationships and cross-references in an Android APK/DEX file.

## Usage

When the user asks about code references, call graphs, who uses a class/method/field, or what a class/method uses:

1. Determine the target (class, method, or field) and query direction
2. Run the JADX AI-CLI usage command
3. Present the reference results

## Command

```bash
jadx-ai usage -c <class-name> [-m <method>] [-f <field>] [-t useIn|used] [-d <depth>] <input-file>
```

## Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `<input-file>` | Yes | Path to APK, DEX, JAR, AAR file |
| `-c, --class` | Yes | Class name to query |
| `-m, --method` | No | Method name (requires --class) |
| `-f, --field` | No | Field name (requires --class) |
| `-t, --type` | No | Query type: `useIn` (who uses this, default) or `used` (what this uses) |
| `-d, --depth` | No | Recursion depth for usage exploration (1=flat, 2+=recursive, default: 1) |

## Query Types

| Type | Description | Available For |
|------|-------------|---------------|
| `useIn` | Who references/uses this node | Class, Method, Field |
| `used` | What this node references/uses | Class (via methods), Method |

## Output Fields

- target: full name of the queried node
- targetType: "class", "method", or "field"
- queryType: "useIn" or "used"
- references: list of {name, nodeType} referencing/referenced nodes (depth=1)
- usageTree: list of {name, nodeType, children} for recursive results (depth>1)
- overrideRelatedMethods: (method only) list of override-related method full names
- callsSelf: (method only) whether the method calls itself
- unresolvedUsed: (method only) list of unresolved method references

## Examples

```bash
# Who uses this class?
jadx-ai usage -c com.example.MyClass app.apk

# What does this class use?
jadx-ai usage -c com.example.MyClass -t used app.apk

# Who calls this method?
jadx-ai usage -c com.example.MyClass -m myMethod app.apk

# What methods does this method call?
jadx-ai usage -c com.example.MyClass -m myMethod -t used app.apk

# Who references this field?
jadx-ai usage -c com.example.MyClass -f myField app.apk

# Recursive usage exploration (3 levels deep)
jadx-ai usage -c "com.example.NetworkClient" -m "sendRequest" --depth 3 app.apk

# Find what a method calls, recursively
jadx-ai usage -c "com.example.MainActivity" -m "onCreate" -t used --depth 2 app.apk
```
