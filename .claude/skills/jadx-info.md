---
name: jadx-info
description: Get metadata and statistics about an Android APK/DEX file using JADX AI-CLI. Returns file info, class/method/field/resource counts, errors, warnings, version.
---

# JADX Info Skill

Get metadata and statistics about an Android APK/DEX file.

## Usage

When the user asks about an APK file overview, statistics, or metadata:

1. Run the JADX AI-CLI info command
2. Present the structured metadata

## Command

```bash
jadx-ai info <input-file>
```

## Output Format

```json
{
  "success": true,
  "data": {
    "fileName": "app.apk",
    "filePath": "/path/to/app.apk",
    "fileSize": 12345678,
    "totalClasses": 1500,
    "totalPackages": 45,
    "totalMethods": 12000,
    "totalFields": 8000,
    "totalResources": 45,
    "errorsCount": 0,
    "warnsCount": 3,
    "version": "1.5.1",
    "errorsReport": "..."
  }
}
```

## Examples

```bash
# Get APK overview
jadx-ai info app.apk
```
