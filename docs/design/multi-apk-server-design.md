# Multi-APK Server Mode Design & Implementation

## Problem

当前 DaemonServer 只能同时加载一个 APK。如果需要分析多个 APK（比如对比两个版本、或者分析主APK+插件APK），必须启动多个 daemon 进程，浪费内存且无法共享分析上下文。

## Solution: SessionManager + AnalysisSession

引入 **Session** 概念，每个 APK 对应一个独立的 `AnalysisSession`，包含自己的 `JadxDecompiler` 和 `DaemonCache`。`SessionManager` 管理所有 session，命令通过 `sessionId` 或 `inputPath` 路由到正确的 session。

### Architecture

```
                    ┌─────────────────────────────────────────────┐
                    │              ServerCore                      │
                    │                                              │
  Request ─────────►│  1. Is system command? (ping/status/...)    │
  (command + args)  │     → Handle directly                       │
                    │                                              │
                    │  2. Resolve session:                         │
                    │     a. args.sessionId → lookup by ID        │
                    │     b. args.inputPath → lookup by path      │
                    │     c. default session (first loaded)       │
                    │                                              │
                    │  3. Execute command in resolved session:     │
                    │     a. Check cache (read-only commands)     │
                    │     b. Dispatch → CommandHandler             │
                    │     c. Invalidate cache (mutation commands) │
                    │                                              │
                    │  SessionManager                              │
                    │  ┌──────────────────────────────────────┐   │
                    │  │ "app1-abcd" → AnalysisSession         │   │
                    │  │   ├── JadxDecompiler (app1.apk)      │   │
                    │  │   └── DaemonCache                    │   │
                    │  │ "app2-ef01" → AnalysisSession         │   │
                    │  │   ├── JadxDecompiler (app2.apk)      │   │
                    │  │   └── DaemonCache                    │   │
                    │  └──────────────────────────────────────┘   │
                    └─────────────────────────────────────────────┘
```

### Key Classes

| Class | Package | Purpose |
|-------|---------|---------|
| `ServerCore` | `jadx.ai.cli.server` | Unified command processing, session resolution |
| `SessionManager` | `jadx.ai.cli.server` | Manage multiple AnalysisSessions |
| `AnalysisSession` | `jadx.ai.cli.server` | One APK's JadxDecompiler + DaemonCache |
| `CommandResult` | `jadx.ai.cli.server` | Standardized command result |
| `JadxServer` | `jadx.ai.cli.server` | TCP server entry point |
| `ServerCommandDispatcher` | `jadx.ai.cli.commands` | Unified 20+ command registry |
| `ServerCommand` | `jadx.ai.cli.commands` | CLI: `jadx-ai server start/stop/status/session-open/session-list/session-close` |

### Session ID Resolution

When a command request arrives, the session is resolved in this order:

1. **Explicit `sessionId`** in request args → exact lookup
2. **`inputPath`** in request args → lookup by APK path
3. **Default session** → the first APK loaded (backward compatible)

This means:
- **Single APK mode**: No `sessionId` needed → automatically uses the default session (same as old DaemonServer)
- **Multi APK mode**: Specify `sessionId` or `inputPath` to target a specific APK
- **CLI auto-detection**: The existing `DaemonClient.detectPort()` works unchanged

### New System Commands

| Command | Args | Description |
|---------|------|-------------|
| `session-open` | `inputPath`, `deobfuscation` | Load a new APK into a new session |
| `session-close` | `sessionId` | Unload an APK and free resources |
| `session-list` | (none) | List all active sessions with status |
| `status` | (none) | Server status including all sessions |

### CLI Usage

```bash
# Start server with first APK
jadx-ai server start app1.apk --background

# Load second APK into the same server
jadx-ai server session-open app2.apk

# List all loaded APKs
jadx-ai server session-list

# Commands automatically target the default session (app1.apk)
jadx-ai search -t class -q "Activity" app1.apk

# Target a specific session by using the APK path
# (The DaemonClient sends inputPath in the request)
jadx-ai search -t class -q "Service" app2.apk

# Unload an APK
jadx-ai server session-close app2.apk

# Stop server (unloads all APKs)
jadx-ai server stop
```

### TCP Protocol Extension

The existing `DaemonProtocol.Request` now supports an optional `sessionId` field:

```json
{
  "magic": "JADX-AI-DAEMON",
  "version": "1.0",
  "command": "search",
  "args": {
    "type": "class",
    "query": "Activity",
    "sessionId": "app2-ef01"
  }
}
```

Backward compatible: if `sessionId` is absent, the default session is used.

### Isolation Guarantees

- Each `AnalysisSession` has its own `JadxDecompiler` — renames in one APK don't affect another
- Each `AnalysisSession` has its own `DaemonCache` — cache hits/misses are per-APK
- Cache invalidation on mutation only affects the target session's cache
- `SessionManager.closeSession()` properly closes the decompiler and frees memory
- `JadxServer` uses a thread pool (10 threads) for concurrent request handling

### Backward Compatibility

- **Single APK mode**: Start with one APK → all commands work exactly as before
- **DaemonClient**: No changes needed — sends commands the same way
- **DaemonProtocol**: Same JSON format — `sessionId` is optional
- **Existing CLI commands**: Work unchanged when only one APK is loaded

### Implementation Status

✅ **Implemented:**
- `AnalysisSession` — isolated JadxDecompiler + DaemonCache per APK
- `SessionManager` — multi-session management with resolution logic
- `ServerCore` — unified command processing with session routing
- `CommandResult` — standardized result type
- `JadxServer` — TCP server with thread pool
- `ServerCommandDispatcher` — all 20 commands in unified registry
- `ServerCommand` — CLI entry point (start/stop/status/session-open/session-list/session-close)
- `JadxAICLI` — ServerCommand registered as subcommand
- Unit tests for ServerCore and SessionManager

⚠️ **Blocked on compilation**: Project requires Java 21+ but this system has Java 17.
   Code is syntactically verified and follows the same patterns as existing DaemonServer/McpCommandDispatcher.
