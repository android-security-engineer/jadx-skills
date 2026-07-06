---
name: continuous-analysis
description: Persistent reverse analysis workflow that preserves context across sessions for continuous APK analysis.
---

# Continuous APK Analysis Workflow

Maintain analysis context across multiple sessions using jadx-ai project persistence. This workflow ensures that renames, comments, bookmarks, notes, and search history survive between CLI invocations.

## Prerequisites

- **Recommended**: Start a unified server for persistent state: `jadx-ai server start <apk>`
- **Alternative**: Use daemon mode: `jadx-ai daemon start <apk>`
- **Or**: Use local mode (project auto-saves on each command, but slower)

> **New**: The unified `server` command (`jadx-ai server start`) combines daemon + MCP + HTTP REST API
> with automatic project persistence. See `docs/design/server-mode-design.md` for details.

## Session Start Pattern

Every new analysis session begins by loading context:

```bash
# 1. Start daemon (optional but recommended for speed)
jadx-ai daemon start <apk>

# 2. Load full project context
jadx-ai project summary <apk>
# → Returns: bookmarks, notes, search history, analysis phase, last viewed class, recent commands

# 3. If no project exists, initialize one
jadx-ai project init <apk>
```

**What the summary tells you:**
- `analysisPhase` — where you left off (e.g., "entry-point-discovery", "crypto-analysis")
- `lastViewedClass` — the last class you were analyzing
- `bookmarks` — important classes/methods you've marked
- `analysisNotes` — findings with severity and tags
- `recentSearches` — what you were searching for
- `recentCommands` — your command history

## Phase 1: Entry Point Discovery

```bash
# Find all entry points
jadx-ai navigate -t entry-points <apk>

# Find the main activity
jadx-ai navigate -t main-activity <apk>

# Find the application class
jadx-ai navigate -t application <apk>

# Bookmark key entry points
jadx-ai project bookmark-add -c <main-activity> -l "Main Activity" <apk>
jadx-ai project bookmark-add -c <application-class> -l "Application Class" <apk>

# Set analysis phase
jadx-ai project note-add -c <apk-root> --note "Starting entry point discovery" --severity info --tags "phase" <apk>
```

## Phase 2: Surface Area Analysis

```bash
# Get app overview
jadx-ai info <apk>
jadx-ai signature <apk>

# List all packages to understand structure
jadx-ai list -t package <apk>

# Find Activities, Services, Receivers, Providers
jadx-ai search -t class -q "Activity" <apk>
jadx-ai search -t class -q "Service" <apk>
jadx-ai search -t class -q "Receiver" <apk>

# Bookmark interesting packages
jadx-ai project bookmark-add -c "com.target.app.core" -l "Core business logic" <apk>

# Note key findings
jadx-ai project note-add -c "com.target.app" --note "12 Activities, 3 Services, no ContentProviders" --severity info --tags "surface" <apk>
```

## Phase 3: Security Audit

```bash
# Search for common vulnerability patterns
jadx-ai search -t string -q "http://" <apk>
jadx-ai search -t string -q "api_key" <apk>
jadx-ai search -t string -q "password" <apk>
jadx-ai search -t method -q "encrypt" <apk>
jadx-ai search -t method -q "decrypt" <apk>
jadx-ai search -t class -q "Cipher" <apk>
jadx-ai search -t class -q "WebView" <apk>
jadx-ai search -t class -q "TrustManager" <apk>

# For each finding, add a note with severity
jadx-ai project note-add -c "com.target.app.NetworkHelper" \
  --note "Custom TrustManager - SSL pinning bypass potential" \
  --severity high --tags "ssl,network,bypass" <apk>

jadx-ai project note-add -c "com.target.app.LoginActivity" \
  --note "Hardcoded API key in validateCredentials()" \
  --severity critical --tags "crypto,hardcoded-key" <apk>

# Trace call chains for critical findings
jadx-ai usage -c "com.target.app.CryptoHelper" -m "encrypt" --depth 3 <apk>

# Generate hooks for dynamic verification
jadx-ai hook -t frida -c "com.target.app.CryptoHelper" <apk>
```

## Phase 4: Deep Dive (Iterative)

```bash
# Decompile targets identified in Phase 3
jadx-ai decompile -c <target-class> <apk>

# Trace data flow
jadx-ai usage -c <target-class> -m <target-method> -t useIn --depth 2 <apk>
jadx-ai usage -c <target-class> -m <target-method> -t used --depth 2 <apk>

# Generate call graphs
jadx-ai graph -t call -c <target-class> --depth 4 <apk>

# Add analysis comments directly in code
jadx-ai comment add -c <target-class> -m <target-method> \
  --comment-text "This method leaks the encryption key to logs" \
  --style JAVADOC <apk>

# Rename obfuscated classes as you understand them
jadx-ai rename -t class -c "com.target.a" -n "LoginActivity" <apk>
jadx-ai rename -t method -c "com.target.LoginActivity" -m "a" -n "validateCredentials" <apk>

# Bookmark the renamed class for future reference
jadx-ai project bookmark-add -c "com.target.LoginActivity" -l "Authentication flow" <apk>
```

## Phase 5: Export & Report

```bash
# Export renamed and commented code
jadx-ai export -o ./analysis-output --save-all <apk>

# View all findings
jadx-ai project notes <apk>

# View all bookmarks
jadx-ai project bookmarks <apk>

# Save project state
jadx-ai project save <apk>
```

## Session Resume Pattern

When returning to an APK after a break:

```bash
# 1. Get full context
jadx-ai project summary <apk>

# 2. Check what phase we were in
# → "crypto-analysis" — we were analyzing crypto operations

# 3. Check last viewed class
# → "com.target.app.CryptoHelper" — pick up from here

# 4. Check notes for outstanding items
jadx-ai project notes --severity high <apk>

# 5. Continue analysis from where we left off
jadx-ai decompile -c "com.target.app.CryptoHelper" <apk>
```

## Multi-Session Analysis Log

The project automatically tracks all commands and their results. To review:

```bash
# View recent analysis activity
jadx-ai project history --limit 50 <apk>

# View only high-severity findings
jadx-ai project notes --severity high <apk>

# View only crypto-related findings
jadx-ai project notes --tags crypto <apk>
```

## AI Agent Integration Pattern

For AI agents (via MCP or CLI), the recommended session loop is:

```
1. Start: Load project summary → understand context
2. Plan: Based on phase and findings, decide next analysis steps
3. Execute: Run search/decompile/usage commands
4. Record: Add notes and bookmarks for findings
5. Iterate: Continue until analysis goals are met
6. End: Save project, update analysis phase
```

The `project summary` command is the key enabler — it gives the agent everything it needs to make informed decisions about what to analyze next, without re-discovering what was already found.
