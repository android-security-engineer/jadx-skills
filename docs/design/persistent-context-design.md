# Persistent Context Design for Continuous APK Reverse Analysis

## Problem Statement

When continuously reverse-engineering an APK across multiple CLI invocations, all analysis state is lost between calls:

1. **Renames vanish** — `rename` changes live only in the JVM process lifetime; the next `jadx-ai` invocation starts fresh
2. **Comments disappear** — `comment add` annotations are never persisted; hours of analyst notes are lost
3. **Search context lost** — every invocation must re-discover entry points, re-trace call chains
4. **No analysis memory** — the analyst (human or AI) must rebuild mental models from scratch each session
5. **Daemon is memory-only** — even the persistent daemon holds everything in RAM; a restart kills all state

This document designs a **project persistence system** that preserves full analysis context across CLI invocations, daemon restarts, and even machine boundaries.

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────┐
│                    AI Agent / Human Analyst                    │
└───────────┬──────────────────────────────────┬────────────────┘
            │ CLI (jadx-ai <cmd>)              │ MCP (stdio)
            ▼                                  ▼
┌─────────────────────────┐    ┌────────────────────────────┐
│   DaemonClient          │    │   McpCommandDispatcher      │
│   (auto-detect daemon)  │    │   (JSON-RPC 2.0)           │
└───────────┬─────────────┘    └──────────┬─────────────────┘
            │                             │
            ▼                             ▼
┌─────────────────────────────────────────────────────────────┐
│                     DaemonServer                              │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────┐  │
│  │ JadxDecompir │  │ ProjectMgr  │  │  DaemonCache       │  │
│  │   (in-mem)   │  │ (load/save) │  │  (TTL cache)       │  │
│  └──────────────┘  └──────┬───────┘  └───────────────────┘  │
└────────────────────────────┼─────────────────────────────────┘
                             │
                             ▼
                    ┌────────────────┐
                    │  .jadx Project │  ← Compatible with GUI's
                    │  File (JSON)   │    JadxProject format
                    └────────────────┘
```

---

## Core Design: `.jadx` Project Files

### Format Compatibility

The CLI project format **extends** the GUI's existing `ProjectData` format, remaining backward-compatible. A `.jadx` file saved by the CLI can be opened in the GUI, and vice versa.

**Base fields (from GUI's `ProjectData`):**
```json
{
  "projectVersion": 2,
  "files": ["/path/to/app.apk"],
  "treeExpansionsV2": [],
  "codeData": {
    "comments": [],
    "renames": []
  },
  "openTabs": [],
  "mappingsPath": null,
  "cacheDir": null,
  "enableLiveReload": false,
  "searchHistory": [],
  "searchResourcesFilter": "*",
  "searchResourcesSizeLimit": 0,
  "pluginOptions": {}
}
```

**CLI-extended fields:**
```json
{
  "...": "(all base fields above)",
  "analysisNotes": [
    {
      "id": "note-001",
      "timestamp": "2026-06-22T14:30:00Z",
      "target": "Lcom/example/app/LoginActivity;",
      "targetType": "class",
      "note": "Uses hardcoded API key in validateCredentials()",
      "severity": "high",
      "tags": ["security", "crypto", "hardcoded-key"]
    }
  ],
  "bookmarks": [
    {
      "target": "Lcom/example/app/NetworkHelper;",
      "label": "Network layer",
      "addedAt": "2026-06-22T14:35:00Z"
    }
  ],
  "analysisLog": [
    {
      "timestamp": "2026-06-22T14:30:00Z",
      "command": "search -t class -q Activity",
      "resultSummary": "Found 12 Activity classes",
      "session": "sess-abc123"
    }
  ],
  "sessionState": {
    "lastViewedClass": "Lcom/example/app/LoginActivity;",
    "activeSession": "sess-abc123",
    "analysisPhase": "entry-point-discovery"
  }
}
```

### Project File Location Strategy

The project file is stored **alongside** the input file:

| Input | Project File Location |
|-------|----------------------|
| `/data/app.apk` | `/data/app.jadx` |
| `/data/app.apk` (if `app.jadx` exists) | `/data/app.jadx` (reuse) |
| `/data/classes.dex` | `/data/classes.jadx` |

The daemon also supports an explicit `--project` flag:

```bash
jadx-ai --project /custom/path/project.jadx info app.apk
```

---

## Component Design

### 1. ProjectManager (New Class)

**File:** `jadx-ai-cli/src/main/java/jadx/ai/cli/project/ProjectManager.java`

```java
package jadx.ai.cli.project;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import com.google.gson.*;

import jadx.api.JadxArgs;
import jadx.api.data.ICodeComment;
import jadx.api.data.ICodeRename;
import jadx.api.data.impl.JadxCodeData;

public class ProjectManager {
    private static final String PROJECT_EXTENSION = "jadx";
    private static final int SEARCH_HISTORY_LIMIT = 30;
    private static final int ANALYSIS_LOG_LIMIT = 500;

    private Path projectPath;
    private ProjectData data;
    private boolean autoSave;
    private final Gson gson;

    // Load existing project or create new
    public static ProjectManager forInput(File inputFile) { ... }
    public static ProjectManager load(Path projectPath) { ... }

    // Lifecycle
    public void fillJadxArgs(JadxArgs args) { ... }
    public void syncFromDecompiler(JadxDecompiler decompiler) { ... }
    public void save() { ... }

    // CodeData mutations (auto-persist on change)
    public void addComment(ICodeComment comment) { ... }
    public void updateComment(ICodeComment old, ICodeComment updated) { ... }
    public void removeComment(ICodeComment comment) { ... }
    public void addRename(ICodeRename rename) { ... }
    public void removeRename(ICodeRename rename) { ... }

    // Search history
    public void addToSearchHistory(String query) { ... }
    public List<String> getSearchHistory() { ... }

    // Analysis notes
    public void addNote(AnalysisNote note) { ... }
    public List<AnalysisNote> getNotes(String targetFilter) { ... }
    public void removeNote(String noteId) { ... }

    // Bookmarks
    public void addBookmark(String target, String label) { ... }
    public List<Bookmark> getBookmarks() { ... }
    public void removeBookmark(String target) { ... }

    // Analysis log
    public void logCommand(String command, String resultSummary) { ... }
    public List<AnalysisLogEntry> getRecentLog(int limit) { ... }

    // Session state
    public void setLastViewedClass(String className) { ... }
    public void setAnalysisPhase(String phase) { ... }
}
```

### 2. ProjectData (CLI Extended)

**File:** `jadx-ai-cli/src/main/java/jadx/ai/cli/project/ProjectData.java`

Reuses GUI's `ProjectData` base and adds CLI-specific extensions:

```java
package jadx.ai.cli.project;

import java.nio.file.Path;
import java.util.*;
import jadx.api.data.impl.JadxCodeData;

public class ProjectData {
    // === Base fields (compatible with GUI) ===
    private int projectVersion = 2;
    private List<Path> files = new ArrayList<>();
    private List<String> treeExpansionsV2 = new ArrayList<>();
    private JadxCodeData codeData = new JadxCodeData();
    private List<TabViewState> openTabs = Collections.emptyList();
    private Path mappingsPath;
    private String cacheDir;
    private boolean enableLiveReload = false;
    private List<String> searchHistory = new ArrayList<>();
    private String searchResourcesFilter = "*";
    private int searchResourcesSizeLimit = 0;
    private Map<String, String> pluginOptions = new HashMap<>();

    // === CLI-extended fields ===
    private List<AnalysisNote> analysisNotes = new ArrayList<>();
    private List<Bookmark> bookmarks = new ArrayList<>();
    private List<AnalysisLogEntry> analysisLog = new ArrayList<>();
    private SessionState sessionState = new SessionState();
}
```

### 3. AnalysisNote

```java
package jadx.ai.cli.project;

import java.util.*;

public class AnalysisNote {
    private String id;           // UUID
    private String timestamp;    // ISO 8601
    private String target;       // Full class/method/field ref
    private String targetType;    // "class", "method", "field", "package"
    private String note;         // Free-text analysis note
    private String severity;     // "info", "low", "medium", "high", "critical"
    private List<String> tags;   // Categorization tags
}
```

### 4. Bookmark

```java
package jadx.ai.cli.project;

public class Bookmark {
    private String target;       // Full class/method ref
    private String label;        // Human-readable label
    private String addedAt;      // ISO 8601
}
```

### 5. AnalysisLogEntry

```java
package jadx.ai.cli.project;

public class AnalysisLogEntry {
    private String timestamp;    // ISO 8601
    private String command;      // CLI command string
    private String resultSummary; // Brief result description
    private String session;      // Session identifier
}
```

### 6. SessionState

```java
package jadx.ai.cli.project;

public class SessionState {
    private String lastViewedClass;
    private String activeSession;    // Session UUID
    private String analysisPhase;    // e.g., "entry-point-discovery", "crypto-analysis"
}
```

---

## Integration Points

### A. AbstractCommand Integration

The `AbstractCommand.run()` method loads the project before creating the decompiler:

```java
@Override
public void run() {
    // Phase 1: Try daemon mode (existing logic)
    if (inputFile != null && !isDaemonCommand()) {
        DaemonClient daemonClient = new DaemonClient();
        int daemonPort = daemonClient.detectPort();
        if (daemonPort > 0) {
            try {
                DaemonProtocol.Response resp = daemonClient.sendCommand(
                        getDaemonCommandName(), buildDaemonArgs(), daemonPort);
                if (resp.success) {
                    System.out.println(GSON.toJson(resp.data));
                    return;
                }
            } catch (Exception ignored) {}
        }
    }

    // Phase 2: Local mode with project persistence
    JadxDecompiler decompiler = null;
    try {
        this.jadxArgs = new JadxArgs();
        jadxArgs.setInputFile(inputFile);

        // NEW: Load project and inject persisted state
        ProjectManager project = ProjectManager.forInput(inputFile);
        project.fillJadxArgs(jadxArgs);  // injects codeData, mappingsPath, pluginOptions

        // ... (existing JadxArgs mapping) ...

        decompiler = new JadxDecompiler(jadxArgs);
        decompiler.load();

        Object result = execute(decompiler);

        // NEW: Sync mutations back to project and save
        project.syncFromDecompiler(decompiler);
        project.save();

        outputResult(result, System.out);
    } catch (Exception e) {
        // ... (existing error handling) ...
    } finally {
        if (decompiler != null) {
            decompiler.close();
        }
    }
}
```

### B. DaemonServer Integration

The daemon holds a `ProjectManager` instance and auto-saves on mutations:

```java
public class DaemonServer {
    private JadxDecompiler decompiler;
    private ProjectManager project;  // NEW
    // ...

    public void start() throws Exception {
        // Load project alongside decompiler
        project = ProjectManager.forInput(jadxArgs.getInputFiles().get(0));
        project.fillJadxArgs(jadxArgs);

        decompiler = new JadxDecompiler(jadxArgs);
        decompiler.load();
        // ...
    }

    private DaemonProtocol.Response dispatch(DaemonProtocol.Request request) {
        // ... existing dispatch logic ...

        // For mutation commands (rename, comment add/delete, reload):
        // After execution, sync and auto-save
        if (!isReadOnlyCommand(request.command)) {
            project.syncFromDecompiler(decompiler);
            project.save();
        }
    }
}
```

### C. Command-Specific Project Interactions

#### RenameCommand
- After renaming: `project.addRename(rename)` → auto-save
- On `--remove-alias`: `project.removeRename(rename)` → auto-save

#### CommentCommand
- After adding: `project.addComment(comment)` → auto-save
- After updating: `project.updateComment(old, new)` → auto-save
- After deleting: `project.removeComment(comment)` → auto-save

#### SearchCommand
- On each search: `project.addToSearchHistory(query)`

#### DecompileCommand
- On class decompilation: `project.sessionState.setLastViewedClass(className)`

---

## ProjectCommand (New CLI Command)

A dedicated command for managing project state directly:

```bash
# Create or load a project
jadx-ai project init app.apk

# Show project status
jadx-ai project status app.apk

# List all bookmarks
jadx-ai project bookmarks app.apk

# Add a bookmark
jadx-ai project bookmark-add -c "com.example.LoginActivity" -l "Auth entry" app.apk

# Remove a bookmark
jadx-ai project bookmark-remove -c "com.example.LoginActivity" app.apk

# List analysis notes
jadx-ai project notes app.apk

# Add an analysis note
jadx-ai project note-add -c "com.example.CryptoHelper" --note "AES key derived from hardcoded seed" --severity high --tags "crypto,hardcoded" app.apk

# Remove a note
jadx-ai project note-remove --id "note-001" app.apk

# View command history / analysis log
jadx-ai project history --limit 20 app.apk

# Export project summary for AI context
jadx-ai project summary app.apk

# Save project explicitly
jadx-ai project save app.apk

# Reset project (clear all annotations, keep files)
jadx-ai project reset app.apk
```

**Picocli definition:**

```java
@Command(name = "project", description = "Manage persistent analysis project state",
         subcommands = {
             ProjectInitCommand.class,
             ProjectStatusCommand.class,
             ProjectBookmarksCommand.class,
             ProjectNotesCommand.class,
             ProjectHistoryCommand.class,
             ProjectSummaryCommand.class,
             ProjectSaveCommand.class,
             ProjectResetCommand.class
         })
public class ProjectCommand extends AbstractCommand {
    @Override
    protected Object execute(JadxDecompiler decompiler) throws Exception {
        // Default: show project status
        ProjectManager project = ProjectManager.forInput(inputFile);
        return project.getStatusSummary();
    }
}
```

---

## Project Summary for AI Context

The most critical feature for continuous AI-driven analysis is the `project summary` command, which generates a structured context document that an AI agent can consume at the start of a session:

```bash
jadx-ai project summary app.apk
```

**Output:**
```json
{
  "projectFile": "/data/app.jadx",
  "inputFile": "app.apk",
  "lastAnalyzed": "2026-06-22T16:00:00Z",
  "totalClasses": 3421,
  "analysisPhase": "crypto-analysis",
  "lastViewedClass": "Lcom/example/app/CryptoHelper;",
  "bookmarks": [
    {"target": "Lcom/example/app/LoginActivity;", "label": "Auth entry"},
    {"target": "Lcom/example/app/NetworkHelper;", "label": "Network layer"},
    {"target": "Lcom/example/app/CryptoHelper;", "label": "Crypto operations"}
  ],
  "recentSearches": ["Cipher", "encrypt", "http://", "api_key", "LoginActivity"],
  "analysisNotes": [
    {
      "id": "note-001",
      "target": "Lcom/example/app/LoginActivity;",
      "note": "Uses hardcoded API key in validateCredentials()",
      "severity": "high",
      "tags": ["security", "crypto", "hardcoded-key"]
    },
    {
      "id": "note-002",
      "target": "Lcom/example/app/NetworkHelper;",
      "note": "SSL pinning bypass via custom TrustManager",
      "severity": "medium",
      "tags": ["network", "ssl", "bypass"]
    }
  ],
  "recentCommands": [
    {"command": "search -t class -q Cipher", "summary": "Found 3 classes"},
    {"command": "decompile -c com.example.app.CryptoHelper", "summary": "Decompiled successfully"},
    {"command": "usage -c com.example.app.CryptoHelper -m encrypt", "summary": "Used in 2 methods"}
  ],
  "codeData": {
    "commentCount": 5,
    "renameCount": 23
  },
  "sessions": [
    {
      "id": "sess-abc123",
      "started": "2026-06-22T14:00:00Z",
      "commands": 47,
      "phase": "entry-point-discovery"
    }
  ]
}
```

An AI agent workflow would start every session with:

```bash
jadx-ai project summary app.apk
```

This gives the agent full context of **what has been analyzed, what was found, where the analyst left off**, and **what the next logical steps are**.

---

## Daemon Enhancements

### Missing Daemon Command Registration

The daemon currently registers **16 commands** but 20 exist. Missing from `buildRegistry()`:

| Command | Should Be Registered? | Implementation |
|---------|---------------------|----------------|
| `graph` | ✅ Yes — read-only | `executeGraph(args)` |
| `hook` | ✅ Yes — read-only | `executeHook(args)` |
| `navigate` | ✅ Yes — read-only | `executeNavigate(args)` |
| `comment` | ⚠️ Partial — `add/update/delete` are mutations | Split: `comment list/search` = cached, `comment add/update/delete` = uncached |
| `cfg` | ✅ Yes — read-only | Already registered |
| `signature` | ✅ Yes — read-only | Already registered |

### Project Persistence in Daemon

```java
public class DaemonServer {
    private ProjectManager project;

    public void start() throws Exception {
        project = ProjectManager.forInput(jadxArgs.getInputFiles().get(0));
        project.fillJadxArgs(jadxArgs);
        // ... rest of start logic ...
    }

    // New daemon commands
    reg.register("project-status", args -> project.getStatusSummary());
    reg.register("project-save", args -> { project.save(); return Map.of("saved", true); });
    reg.register("project-summary", args -> project.getFullSummary());
    reg.register("bookmark-add", args -> {
        project.addBookmark((String) args.get("target"), (String) args.get("label"));
        return Map.of("added", true);
    });
    reg.register("bookmark-list", args -> project.getBookmarks());
    reg.register("bookmark-remove", args -> {
        project.removeBookmark((String) args.get("target"));
        return Map.of("removed", true);
    });
    reg.register("note-add", args -> {
        project.addNote(AnalysisNote.fromMap(args));
        return Map.of("added", true);
    });
    reg.register("note-list", args -> project.getNotes((String) args.get("target")));
    reg.register("note-remove", args -> {
        project.removeNote((String) args.get("id"));
        return Map.of("removed", true);
    });
    reg.register("note-update", args -> {
        project.updateNote((String) args.get("id"), (String) args.get("note"));
        return Map.of("updated", true);
    });
    reg.register("history", args -> {
        int limit = args.containsKey("limit") ? ((Number) args.get("limit")).intValue() : 20;
        return project.getRecentLog(limit);
    });
}
```

### Auto-Save Strategy

- **Mutation commands** (rename, comment add/update/delete, bookmark, note) → auto-save immediately
- **Search/Decompile/List** (read-only) → update searchHistory and sessionState, then batch-save every 60 seconds
- **Daemon shutdown** → save all pending changes
- **Configurable via** `--auto-save on|off` (default: on)

---

## MCP Tool Additions

Add 5 new MCP tools for project state management:

### jadx_project_summary
```json
{
  "name": "jadx_project_summary",
  "description": "Get a comprehensive summary of the current analysis project state including bookmarks, notes, search history, and session context",
  "inputSchema": {
    "type": "object",
    "properties": {}
  }
}
```

### jadx_bookmark
```json
{
  "name": "jadx_bookmark",
  "description": "Add, remove, or list bookmarks for classes and methods of interest",
  "inputSchema": {
    "type": "object",
    "properties": {
      "action": {"type": "string", "enum": ["add", "remove", "list"], "default": "list"},
      "target": {"type": "string", "description": "Full class or method name"},
      "label": {"type": "string", "description": "Bookmark label (for add action)"}
    }
  }
}
```

### jadx_note
```json
{
  "name": "jadx_note",
  "description": "Add, update, remove, or list analysis notes attached to classes, methods, or fields",
  "inputSchema": {
    "type": "object",
    "properties": {
      "action": {"type": "string", "enum": ["add", "update", "remove", "list"], "default": "list"},
      "target": {"type": "string", "description": "Full class/method/field reference"},
      "note": {"type": "string", "description": "Note text (for add/update)"},
      "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"], "default": "info"},
      "tags": {"type": "string", "description": "Comma-separated tags"},
      "id": {"type": "string", "description": "Note ID (for update/remove)"}
    }
  }
}
```

### jadx_history
```json
{
  "name": "jadx_history",
  "description": "View recent command execution history and analysis log",
  "inputSchema": {
    "type": "object",
    "properties": {
      "limit": {"type": "integer", "description": "Maximum entries to return", "default": 20}
    }
  }
}
```

### jadx_project_save
```json
{
  "name": "jadx_project_save",
  "description": "Explicitly save the current project state to disk",
  "inputSchema": {
    "type": "object",
    "properties": {}
  }
}
```

---

## Continuous Analysis Workflow Pattern

With project persistence, a typical AI agent session follows this pattern:

### Session Start
```bash
# 1. Start daemon if not running
jadx-ai daemon start app.apk

# 2. Load project context
jadx-ai project summary app.apk
# → Returns full context: bookmarks, notes, search history, analysis phase

# 3. Resume from where we left off
# The summary tells us we were in "crypto-analysis" phase,
# last viewed CryptoHelper, found hardcoded key and SSL bypass
```

### Analysis Loop
```bash
# 4. Continue analysis based on context
jadx-ai decompile -c com.example.app.CryptoHelper app.apk
jadx-ai usage -c com.example.app.CryptoHelper -m encrypt --depth 2 app.apk
jadx-ai note-add -c com.example.app.DataStore --note "Encrypts data before storage" --severity medium --tags "crypto,data" app.apk
jadx-ai bookmark-add -c com.example.app.DataStore -l "Data persistence" app.apk
jadx-ai search -t string -q "password" app.apk

# Each command auto-persists to the .jadx project file
```

### Session End
```bash
# 5. Save and update session state
jadx-ai project save app.apk
# → All renames, comments, bookmarks, notes, search history persisted

# 6. Next session picks up seamlessly
jadx-ai project summary app.apk
# → Shows everything from last session
```

---

## Implementation Plan

### Phase 1: Core Project Persistence (Priority: Critical)

1. **Create `ProjectManager` class** with load/save/merge logic
2. **Create `ProjectData` (CLI-extended)** with Gson serialization
3. **Create `AnalysisNote`, `Bookmark`, `AnalysisLogEntry`, `SessionState`** data classes
4. **Integrate into `AbstractCommand.run()`** — load project before decompiler, save after
5. **Integrate into `DaemonServer`** — load on start, save on mutations and shutdown
6. **Add missing daemon commands** — graph, hook, navigate, comment (mutation half)

### Phase 2: ProjectCommand (Priority: High)

7. **Create `ProjectCommand`** with subcommands (init, status, bookmarks, notes, history, summary, save, reset)
8. **Wire project subcommands** into `JadxAICLI.java` picocli registration

### Phase 3: MCP Integration (Priority: High)

9. **Add 5 new MCP tool definitions** to `McpToolDefinitions`
10. **Add 5 new dispatch methods** to `McpCommandDispatcher`
11. **Wire MCP tools** to ProjectManager methods

### Phase 4: Workflow Enhancement (Priority: Medium)

12. **Update workflow skill files** to use `project summary` at session start
13. **Create continuous-analysis workflow** skill
14. **Add `--project` flag** to AbstractCommand for explicit project path
15. **Add `--auto-save` flag** to control persistence behavior

---

## Compatibility Notes

### GUI Interop
- CLI `.jadx` files are fully compatible with GUI's `JadxProject` format
- CLI-extended fields (`analysisNotes`, `bookmarks`, `analysisLog`, `sessionState`) are silently ignored by the GUI
- GUI-extended fields (`openTabs`, `treeExpansionsV2`) are silently ignored by the CLI

### Backward Compatibility
- If no `.jadx` file exists, the CLI behaves exactly as before (no persistence)
- If a `.jadx` file exists but has no CLI-extended fields, everything works normally
- The `project` command is optional — state persists automatically for mutation commands

### File Safety
- Project saves are atomic (write to temp file, then rename)
- Corrupted `.jadx` files are detected and reported; analysis continues without persistence
- Concurrent access is handled by file locking (pid file for daemon)

---

## Summary

This design enables the core capability for **continuous reverse analysis**: the ability to pick up an APK analysis session exactly where you left off, with all renames, comments, bookmarks, analysis notes, and search history preserved. The key innovations are:

1. **Extending the GUI's `.jadx` format** with CLI-specific fields for notes, bookmarks, and analysis log
2. **Auto-save on mutations** — rename and comment operations automatically persist
3. **Project summary as context** — AI agents get full analysis state in a single call
4. **Daemon integration** — the persistent daemon holds project state in memory and saves to disk
5. **MCP tool exposure** — project state management available to AI agents via MCP
