---
name: jadx-line-map
description: Get decompiled-to-source line mapping, code annotations, and position-to-node resolution from Android APK using JADX AI-CLI. Maps decompiled line numbers back to original source lines, resolves code positions to JavaNodes, and queries annotations.
---

# JADX Line Map Skill

Get decompiled-to-source line mapping, code position annotations, and position-to-node resolution.

## Usage

When the user asks about line number mapping, source line tracing, code annotations at positions, or what code element is at a specific position:

1. Run the JADX AI-CLI line-map command
2. Present the structured results

## Command

```bash
jadx-ai line-map -c <class-name> [--annotations] [--usage-map] [--use-places <node>] [--source-line <line>] [--node-at <pos>] [--closest-node <pos>] [--enclosing-node <pos>] [--annotation-at <pos>] <input-file>
```

## Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `<input-file>` | Yes | Path to APK, DEX file |
| `-c, --class` | Yes | Full class name |
| `--annotations` | No | Include code annotations (node refs at each position) |
| `--usage-map` | No | Include usage map (position → node mapping) |
| `--use-places` | No | Show use places for a specific node (format: class.method or class.field) |
| `--source-line` | No | Get source line for a specific decompiled line number |
| `--node-at` | No | Get JavaNode at exact position (character offset) |
| `--closest-node` | No | Get closest JavaNode above position (character offset) |
| `--enclosing-node` | No | Get enclosing node (class/method) at position (character offset) |
| `--annotation-at` | No | Get code annotation at position (character offset) |

## Output Fields

- className: full class name
- lineMap: list of {decompiledLine, sourceLine} mappings
- annotations: (with --annotations) list of {position, type, nodeFullName, nodeType}
- usageMap: (with --usage-map) list of {position, nodeFullName, nodeType}
- usePlaces: (with --use-places) list of position integers where the node is used
- sourceLineResult: (with --source-line) source line number for the given decompiled line
- nodeAtPosition: (with --node-at) {fullName, nodeType, defPos, declaringClass} or empty object
- closestNode: (with --closest-node) {fullName, nodeType, defPos, declaringClass} or empty object
- enclosingNode: (with --enclosing-node) {fullName, nodeType, defPos, declaringClass} or empty object
- annotationAt: (with --annotation-at) {position, type, nodeFullName, nodeType}

## Examples

```bash
# Get line mapping
jadx-ai line-map -c com.example.MyClass app.apk

# Get line mapping with annotations
jadx-ai line-map -c com.example.MyClass --annotations app.apk

# Get line mapping with usage map
jadx-ai line-map -c com.example.MyClass --usage-map app.apk

# Get use places for a specific method
jadx-ai line-map -c com.example.MyClass --use-places MyClass.myMethod app.apk

# Get source line for decompiled line 10
jadx-ai line-map -c com.example.MyClass --source-line 10 app.apk

# Get node at exact position
jadx-ai line-map -c com.example.MyClass --node-at 150 app.apk

# Get closest node above position
jadx-ai line-map -c com.example.MyClass --closest-node 150 app.apk

# Get enclosing class/method at position
jadx-ai line-map -c com.example.MyClass --enclosing-node 150 app.apk

# Get annotation at position
jadx-ai line-map -c com.example.MyClass --annotation-at 150 app.apk
```
