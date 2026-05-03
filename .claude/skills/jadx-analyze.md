---
name: jadx-analyze
description: Comprehensive analysis of Android APK/DEX files using JADX AI-CLI. Combines info, search, decompile, resources, usage, and class-detail into a guided workflow.
---

# JADX Analyze Skill

Comprehensive analysis workflow for Android APK/DEX files. This skill chains multiple JADX commands together for deeper analysis.

## Usage

When the user asks to analyze, reverse engineer, or understand an Android app:

1. **Step 1: Get overview** - Run `jadx-info` to understand the app scale
2. **Step 2: Explore structure** - Run `jadx-list` to browse packages and classes
3. **Step 3: Search targets** - Run `jadx-search` to find specific classes/methods/strings
4. **Step 4: Decompile targets** - Run `jadx-decompile` to read source code
5. **Step 5: Analyze resources** - Run `jadx-resources` to access AndroidManifest, layouts, etc.
6. **Step 6: Trace relationships** - Run `jadx-usage` to find call graphs and references
7. **Step 7: Get class details** - Run `jadx-class-detail` for inheritance and method signatures
8. **Step 8: Export if needed** - Run `jadx-export` to save results

## Workflow Commands

```bash
# Step 1: Overview
jadx-ai info <input-file>

# Step 2: List packages
jadx-ai list -t packages <input-file>

# Step 3: Search for entry points
jadx-ai search -t class -q Activity <input-file>
jadx-ai search -t method -q onCreate <input-file>

# Step 4: Decompile interesting classes
jadx-ai decompile -c <class-name> <input-file>

# Step 5: Analyze resources (AndroidManifest, layouts, etc.)
jadx-ai resources --include-resources <input-file>
jadx-ai resources --include-resources -t MANIFEST <input-file>

# Step 6: Trace call graph and references
jadx-ai usage -c <class-name> <input-file>
jadx-ai usage -c <class-name> -m <method-name> <input-file>

# Step 7: Get detailed class structure
jadx-ai class-detail -c <class-name> <input-file>

# Step 8: Export for further analysis
jadx-ai export -o ./analysis-output -p <package> <input-file>
```

## Common Analysis Patterns

### Find the main Activity
```bash
jadx-ai search -t class -q MainActivity <apk>
jadx-ai decompile -c <found-class> <apk>
```

### Find network endpoints
```bash
jadx-ai search -t string -q "http" <apk>
jadx-ai search -t method -q Retrofit <apk>
```

### Find crypto usage
```bash
jadx-ai search -t method -q encrypt <apk>
jadx-ai search -t method -q decrypt <apk>
jadx-ai search -t class -q Cipher <apk>
```

### Find authentication logic
```bash
jadx-ai search -t method -q login <apk>
jadx-ai search -t method -q authenticate <apk>
jadx-ai search -t string -q "token" <apk>
```
