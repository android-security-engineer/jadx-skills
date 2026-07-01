# JADX Server Mode Design — Unified Persistent Analysis Server

## Motivation

当前 jadx-ai-cli 有两个独立的"服务器"实现，各自都有严重局限：

| 现有组件 | 协议 | 持久化 | 问题 |
|---------|------|--------|------|
| DaemonServer | TCP (自定义JSON) | ❌ 纯内存 | 重启丢失所有状态；缺4个命令；没有项目持久化 |
| McpCommand | stdio (JSON-RPC 2.0) | ❌ 无 | 每次启动重新加载APK；MCP连接断开即丢失状态 |

**用户的核心需求**：当我们持续逆向分析一个 APK 时，如何让分析状态（重命名、注释、搜索历史、分析笔记、书签）跨会话持久化？

**答案**：引入统一的 **Server Mode**，将 Daemon 的常驻内存优势 + MCP 的 AI Agent 集成 + 项目文件持久化 三者合一。

---

## Architecture: Unified JADX Server

```
                              ┌───────────────────────────────┐
                              │      JADX Server (JVM)        │
                              │                               │
  ┌──────────┐  TCP:17530    │  ┌─────────────────────────┐   │
  │  CLI     │───────────────│──│  TcpTransport           │   │
  │  Client  │               │  └──────────┬──────────────┘   │
  └──────────┘               │             │                  │
                              │  ┌──────────▼──────────────┐   │
  ┌──────────┐  stdio        │  │                         │   │
  │  AI      │───────────────│──│  ServerCore             │   │
  │  Agent   │  (MCP)       │  │  ┌───────────────────┐   │   │
  │  (Claude)│               │  │  │ JadxDecompiler    │   │   │
  └──────────┘               │  │  └───────────────────┘   │   │
                              │  │  ┌───────────────────┐   │   │
  ┌──────────┐  HTTP:17531   │  │  │ ProjectManager    │   │   │
  │  Browser │───────────────│──│  │ (load/save .jadx) │   │   │
  │  /curl   │  (REST API)   │  │  └───────────────────┘   │   │
  └──────────┘               │  │  ┌───────────────────┐   │   │
                              │  │  │ DaemonCache       │   │   │
                              │  │  └───────────────────┘   │   │
                              │  │  ┌───────────────────┐   │   │
                              │  │  │ EventDispatcher   │   │   │
                              │  │  └───────────────────┘   │   │
                              │  └─────────────────────────┘   │
                              │             │                  │
                              │  ┌──────────▼──────────────┐   │
                              │  │    Transport Layer       │   │
                              │  │  ┌─────┐ ┌─────┐ ┌────┐ │   │
                              │  │  │ TCP │ │MCP  │ │HTTP│ │   │
                              │  │  │:17530│ │stdio│ │:17531│ │   │
                              │  │  └─────┘ └─────┘ └────┘ │   │
                              │  └─────────────────────────┘   │
                              └───────────────────────────────┘
                                            │
                                            ▼
                                  ┌────────────────────┐
                                  │  .jadx Project File │
                                  │  (auto-save)        │
                                  └────────────────────┘
```

### Core Principle: **ServerCore 是唯一的命令处理中心**

所有 Transport（TCP/MCP/HTTP）都通过同一个 `ServerCore` 处理请求，确保：
- 所有命令都通过同一条路径 → 一致的行为
- 项目状态由 ServerCore 统一管理 → 一致的持久化
- 缓存由 ServerCore 统一控制 → 一致的缓存策略

---

## ServerCore Design

```java
package jadx.ai.cli.server;

/**
 * Unified server core — the single source of truth for all command processing.
 * Holds the JadxDecompiler, ProjectManager, and DaemonCache.
 * All transports delegate to this core.
 */
public class ServerCore {

    private JadxDecompiler decompiler;
    private ProjectManager project;
    private DaemonCache cache;
    private CommandDispatcher dispatcher;
    private EventDispatcher events;

    // === Lifecycle ===

    /** Start server: load APK + project, build command registry */
    public void start(JadxArgs args, Path projectPath) throws Exception {
        this.project = ProjectManager.load(projectPath);
        project.fillJadxArgs(args);  // inject codeData, mappingsPath, pluginOptions
        this.decompiler = new JadxDecompiler(args);
        decompiler.load();
        this.cache = new DaemonCache(5 * 60_000, 500);
        this.dispatcher = new CommandDispatcher(decompiler, project, cache);
        this.events = new EventDispatcher();
        project.logEvent("server", "started", "Server started with " + decompiler.getClasses().size() + " classes");
    }

    /** Stop server: save project, close decompiler */
    public void stop() {
        project.syncFromDecompiler(decompiler);
        project.save();
        project.logEvent("server", "stopped", "Server shutting down");
        decompiler.close();
    }

    // === Command Processing (unified entry point) ===

    /** Execute a command — ALL transports call this */
    public CommandResult executeCommand(String command, Map<String, Object> args) {
        long start = System.currentTimeMillis();
        try {
            // Check cache for read-only commands
            boolean isReadOnly = dispatcher.isReadOnlyCommand(command);
            String cacheKey = command + ":" + gson.toJson(args);

            if (isReadOnly && cache != null) {
                Object cached = cache.get(cacheKey);
                if (cached != null) {
                    return CommandResult.cached(cached, System.currentTimeMillis() - start);
                }
            }

            // Dispatch to command handler
            Object result = dispatcher.dispatch(command, args);

            // Cache read-only results
            if (isReadOnly && cache != null) {
                cache.put(cacheKey, result);
            }

            // Auto-save on mutations
            if (!isReadOnly) {
                project.syncFromDecompiler(decompiler);
                project.save();
                cache.invalidateAll();  // mutations invalidate all cached reads
            }

            // Log command execution
            project.logCommand(command, summarize(result));

            return CommandResult.success(result, System.currentTimeMillis() - start);
        } catch (Exception e) {
            return CommandResult.error(e, System.currentTimeMillis() - start);
        }
    }

    // === Status ===

    public ServerStatus getStatus() {
        ServerStatus status = new ServerStatus();
        status.status = "running";
        status.classCount = decompiler.getClasses().size();
        status.uptimeMs = System.currentTimeMillis() - startTime;
        status.memoryUsedMB = (Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()) / (1024 * 1024);
        status.projectPath = project.getProjectPath();
        status.projectDirty = !project.isSaved();
        status.cacheStats = cache.getStats();
        return status;
    }

    public ProjectSummary getProjectSummary() {
        return project.getFullSummary();
    }
}
```

---

## CommandDispatcher (Unified Registry)

统一所有20+命令的注册和分发。替换 DaemonServer.buildRegistry() 和 McpCommandDispatcher 两套独立的分派逻辑。

```java
package jadx.ai.cli.server;

public class CommandDispatcher {

    private final JadxDecompiler decompiler;
    private final ProjectManager project;
    private final DaemonCache cache;

    // All commands registered — single source of truth
    private final Map<String, CommandHandler> handlers = new LinkedHashMap<>();

    public CommandDispatcher(JadxDecompiler decompiler, ProjectManager project, DaemonCache cache) {
        this.decompiler = decompiler;
        this.project = project;
        this.cache = cache;
        registerAllCommands();
    }

    private void registerAllCommands() {
        // === Read-only commands (cacheable) ===
        register("search",       this::executeSearch,       true);
        register("usage",        this::executeUsage,        true);
        register("list",         this::executeList,         true);
        register("info",         this::executeInfo,         true);
        register("class-detail", this::executeClassDetail,  true);
        register("decompile",    this::executeDecompile,    true);
        register("resources",    this::executeResources,    true);
        register("line-map",     this::executeLineMap,      true);
        register("package-detail", this::executePackageDetail, true);
        register("graph",        this::executeGraph,        true);
        register("hook",         this::executeHook,         true);
        register("navigate",     this::executeNavigate,     true);
        register("cfg",          this::executeCfg,          true);
        register("signature",    this::executeSignature,    true);
        register("comment-list", this::executeCommentList,  true);    // read half
        register("comment-search", this::executeCommentSearch, true); // read half

        // === Mutation commands (not cacheable, triggers auto-save) ===
        register("rename",       this::executeRename,       false);
        register("reload",       this::executeReload,       false);
        register("export",       this::executeExport,       false);
        register("comment-add",  this::executeCommentAdd,   false);
        register("comment-update", this::executeCommentUpdate, false);
        register("comment-delete", this::executeCommentDelete, false);
        register("script",       this::executeScript,       false);

        // === Project management commands ===
        register("project-summary", this::executeProjectSummary, true);
        register("project-status",  this::executeProjectStatus,  true);
        register("bookmark-add",    this::executeBookmarkAdd,    false);
        register("bookmark-remove", this::executeBookmarkRemove, false);
        register("bookmark-list",   this::executeBookmarkList,   true);
        register("note-add",        this::executeNoteAdd,        false);
        register("note-update",     this::executeNoteUpdate,     false);
        register("note-remove",     this::executeNoteRemove,     false);
        register("note-list",       this::executeNoteList,       true);
        register("history",         this::executeHistory,        true);

        // === System commands ===
        register("ping",     (args) -> "pong",      true);
        register("status",   this::executeStatus,   true);
        register("shutdown", this::executeShutdown,  false);
        register("cache-stats", this::executeCacheStats, true);
        register("cache-clear", this::executeCacheClear, false);
    }

    private void register(String name, CommandHandler handler, boolean readOnly) {
        handlers.put(name, new RegisteredCommand(handler, readOnly));
    }

    public Object dispatch(String command, Map<String, Object> args) throws Exception {
        RegisteredCommand rc = handlers.get(command);
        if (rc == null) throw new IllegalArgumentException("Unknown command: " + command);
        return rc.handler.apply(args);
    }

    public boolean isReadOnlyCommand(String command) {
        RegisteredCommand rc = handlers.get(command);
        return rc != null && rc.readOnly;
    }

    @FunctionalInterface
    interface CommandHandler {
        Object apply(Map<String, Object> args) throws Exception;
    }

    static class RegisteredCommand {
        final CommandHandler handler;
        final boolean readOnly;
        RegisteredCommand(CommandHandler handler, boolean readOnly) {
            this.handler = handler;
            this.readOnly = readOnly;
        }
    }
}
```

---

## Transport Layer

### 1. TCP Transport (existing DaemonServer protocol, upgraded)

保持向后兼容。现有的 DaemonClient 无需修改。

```java
package jadx.ai.cli.server.transport;

public class TcpTransport {
    private final ServerCore core;
    private final int port;
    private ServerSocket serverSocket;

    public void start() throws Exception {
        serverSocket = new ServerSocket(port);
        while (running) {
            Socket client = serverSocket.accept();
            executor.submit(() -> handleClient(client));
        }
    }

    private void handleClient(Socket client) {
        // Read DaemonProtocol.Request (same format as before)
        // → core.executeCommand(request.command, request.args)
        // → Write DaemonProtocol.Response (same format as before)
    }
}
```

**关键改进**：TCP transport 现在通过 ServerCore 走统一路径，获得项目持久化能力。

### 2. MCP Transport (existing stdio JSON-RPC, upgraded)

保持 stdio JSON-RPC 2.0 协议不变。Claude Desktop / Cursor 等 AI 工具无需修改。

```java
package jadx.ai.cli.server.transport;

public class McpTransport {
    private final ServerCore core;

    public void run() {
        // Read JSON-RPC from stdin (same as before)
        // → handleMethod() now delegates to core.executeCommand()
        // → McpToolDefinitions adds new project tools
    }

    private Object handleToolCall(String toolName, Map<String, Object> args) throws Exception {
        // Map MCP tool name to ServerCore command name
        String command = mcpToCommand(toolName);
        CommandResult result = core.executeCommand(command, args);
        return result.getData();
    }

    private String mcpToCommand(String toolName) {
        // "jadx_search" → "search"
        // "jadx_project_summary" → "project-summary"
        // "jadx_bookmark" → "bookmark-add"/"bookmark-list" based on action param
        return toolName.replace("jadx_", "").replace("_", "-");
    }
}
```

### 3. HTTP Transport (NEW — REST API for web/curl integration)

新增 HTTP REST API，让浏览器、curl、甚至其他语言的客户端都能方便地调用。

```java
package jadx.ai.cli.server.transport;

public class HttpTransport {
    private final ServerCore core;
    private final int port;

    // Simple HTTP server (no external dependencies)
    public void start() throws Exception {
        ServerSocket server = new ServerSocket(port);
        while (running) {
            Socket client = server.accept();
            executor.submit(() -> handleHttpRequest(client));
        }
    }
}
```

**REST API endpoints:**

| Method | Path | ServerCore Command | Description |
|--------|------|-------------------|-------------|
| GET | `/api/status` | status | Server status |
| GET | `/api/info` | info | APK info |
| GET | `/api/classes` | list | List classes |
| GET | `/api/classes/{name}` | class-detail | Class detail |
| GET | `/api/classes/{name}/code` | decompile | Decompiled code |
| GET | `/api/classes/{name}/smali` | decompile (withSmali) | Smali code |
| GET | `/api/classes/{name}/usage` | usage | Class usage |
| GET | `/api/classes/{name}/methods/{method}/cfg` | cfg | Control flow graph |
| GET | `/api/search?q=...&type=...` | search | Search |
| GET | `/api/resources` | resources | List resources |
| GET | `/api/packages/{name}` | package-detail | Package detail |
| GET | `/api/navigate/{type}` | navigate | Navigate entry points |
| GET | `/api/graph?class=...&type=...` | graph | Call/inheritance/usage graph |
| GET | `/api/signature` | signature | APK signature |
| GET | `/api/project/summary` | project-summary | Project context |
| GET | `/api/project/bookmarks` | bookmark-list | List bookmarks |
| GET | `/api/project/notes` | note-list | List notes |
| GET | `/api/project/history` | history | Command history |
| POST | `/api/rename` | rename | Rename class/method/field |
| POST | `/api/comment` | comment-add | Add comment |
| PUT | `/api/comment` | comment-update | Update comment |
| DELETE | `/api/comment` | comment-delete | Delete comment |
| POST | `/api/bookmark` | bookmark-add | Add bookmark |
| DELETE | `/api/bookmark` | bookmark-remove | Remove bookmark |
| POST | `/api/note` | note-add | Add analysis note |
| PUT | `/api/note` | note-update | Update note |
| DELETE | `/api/note` | note-remove | Remove note |
| POST | `/api/export` | export | Export decompiled code |
| POST | `/api/reload` | reload | Reload class/codeData |
| POST | `/api/hook` | hook | Generate hook snippet |
| POST | `/api/shutdown` | shutdown | Shutdown server |

**curl example:**
```bash
# Start server
jadx-ai server start app.apk

# Get APK info
curl http://localhost:17531/api/info

# Decompile a class
curl http://localhost:17531/api/classes/com.example.app.LoginActivity/code

# Search for encryption methods
curl "http://localhost:17531/api/search?q=encrypt&type=method"

# Add analysis note
curl -X POST http://localhost:17531/api/note \
  -H "Content-Type: application/json" \
  -d '{"target":"com.example.app.CryptoHelper","note":"Hardcoded AES key","severity":"critical","tags":["crypto","hardcoded"]}'

# Get project summary (for AI context)
curl http://localhost:17531/api/project/summary
```

---

## Server Start/Stop Flow

### Starting the Server

```bash
# Start server with all transports
jadx-ai server start app.apk

# With options
jadx-ai server start app.apk --tcp-port 17530 --http-port 17531 --project ./my-analysis.jadx

# Start with only MCP (for Claude Desktop integration)
jadx-ai server start app.apk --transport mcp

# Start with only TCP (for CLI client)
jadx-ai server start app.apk --transport tcp

# Start with only HTTP (for web/curl)
jadx-ai server start app.apk --transport http
```

**启动流程：**
```
1. Parse arguments
2. Resolve project file (beside APK or explicit --project)
3. Load ProjectManager → fill JadxArgs
4. Create JadxDecompiler → load APK
5. Start requested transports (TCP, MCP, HTTP)
6. Write PID file
7. Enter main loop (keep alive until shutdown)
8. On shutdown: save project → close decompiler → remove PID file
```

### CLI Client Auto-Detection (Enhanced)

When a CLI command runs, it first checks for a running server:

```java
// In AbstractCommand.run():
// Phase 1: Auto-detect running server
DaemonClient daemonClient = new DaemonClient();
int port = daemonClient.detectPort();
if (port > 0) {
    // Server is running — send command via TCP
    DaemonProtocol.Response resp = daemonClient.sendCommand(commandName, args, port);
    if (resp.success) {
        System.out.println(GSON.toJson(resp.data));
        return;
    }
}
// Phase 2: Local mode (no server running)
// Load project → create decompiler → execute → save project → close
```

This is the **existing** auto-detection behavior — no change needed. The server upgrade is transparent to CLI users.

---

## Session Lifecycle: Continuous Analysis with Persistence

### Session 1: First Analysis

```bash
# 1. Start server — loads APK, creates/opens .jadx project
jadx-ai server start target.apk --background

# 2. CLI commands automatically go through server (via daemon auto-detection)
jadx-ai navigate -t entry-points target.apk
jadx-ai search -t class -q "Login" target.apk
jadx-ai decompile -c com.target.LoginActivity target.apk

# 3. Rename obfuscated class
jadx-ai rename -t class -c "com.target.a" -n "LoginActivity" target.apk
# → Server auto-saves project (codeData updated with new rename)

# 4. Add analysis note
jadx-ai comment add -c com.target.LoginActivity -m validateCredentials \
  --comment-text "Hardcoded API key found here" --style JAVADOC target.apk
# → Server auto-saves project (codeData updated with new comment)

# 5. Stop server — project persisted
jadx-ai daemon stop target.apk
# → Server saves project before shutting down
```

### Session 2: Resume Analysis (Days Later)

```bash
# 1. Start server — loads APK + .jadx project (all renames/comments/notes restored)
jadx-ai server start target.apk --background

# 2. Check project summary — full context from last session
jadx-ai project summary target.apk
# → Returns: renames (1), comments (1), bookmarks (0), notes (0),
#           searchHistory (["Login", ...]), lastViewedClass, analysisPhase

# 3. Continue from where you left off
jadx-ai usage -c com.target.LoginActivity -m validateCredentials target.apk
jadx-ai search -t string -q "api_key" target.apk
# → All previous renames are already applied
```

### AI Agent Session (via MCP)

```bash
# 1. Start server with MCP transport
jadx-ai server start target.apk --transport mcp,tcp

# 2. AI agent connects via MCP stdio
# Claude Desktop / Cursor configuration:
# {
#   "mcpServers": {
#     "jadx": {
#       "command": "jadx-ai",
#       "args": ["server", "start", "target.apk", "--transport", "mcp"]
#     }
#   }
# }

# 3. AI agent calls jadx_project_summary → gets full context
# 4. AI agent calls jadx_search, jadx_decompile, jadx_usage → analyzes APK
# 5. AI agent calls jadx_note_add → records findings
# 6. AI agent calls jadx_rename → renames obfuscated identifiers
# 7. All changes auto-persist to .jadx project file
# 8. Next AI session: jadx_project_summary → picks up from where it left off
```

---

## Project Persistence Integration with ServerCore

The key innovation: **ServerCore owns ProjectManager**, and **every mutation command auto-saves**.

```
                    ┌─────────────────────────────────────────┐
                    │              ServerCore                  │
                    │                                         │
  executeCommand()  │  1. Dispatch to CommandHandler          │
  ─────────────────►│  2. If mutation:                        │
                    │     a. project.syncFromDecompiler()     │
                    │     b. project.save()                    │
                    │     c. cache.invalidateAll()            │
                    │  3. If read-only:                       │
                    │     a. Check cache                      │
                    │     b. Cache miss → execute → cache it  │
                    │  4. project.logCommand()                │
                    │                                         │
                    │  On shutdown:                            │
                    │     project.save()  ← guaranteed        │
                    └─────────────────────────────────────────┘
```

### Auto-Save Strategy

| Event | Action | Rationale |
|-------|--------|-----------|
| rename/comment mutation | Immediate save | User expects persistence |
| bookmark/note mutation | Immediate save | These are explicit user actions |
| search/decompile (read-only) | Update sessionState + searchHistory; batch save every 60s | Too frequent otherwise |
| Server shutdown | Full save | Guaranteed persistence |
| SIGTERM / SIGINT | Full save via shutdown hook | Graceful shutdown |
| JVM crash | Last batch save (up to 60s data loss) | Acceptable tradeoff |

---

## Comparison: Current vs Server Mode

| Aspect | Current (DaemonServer) | Server Mode |
|--------|----------------------|-------------|
| **APK loaded** | ✅ In memory | ✅ In memory |
| **Commands** | 16 registered | 30+ registered (all commands + project) |
| **Cache** | ✅ TTL cache | ✅ TTL cache |
| **Rename persistence** | ❌ Lost on restart | ✅ Auto-saved to .jadx |
| **Comment persistence** | ❌ Lost on restart | ✅ Auto-saved to .jadx |
| **Search history** | ❌ Not tracked | ✅ Persisted in project |
| **Analysis notes** | ❌ Not supported | ✅ Severity + tags |
| **Bookmarks** | ❌ Not supported | ✅ Labeled references |
| **Command history** | ❌ Not tracked | ✅ Full audit log |
| **Session resume** | ❌ Start from scratch | ✅ project summary |
| **MCP integration** | ❌ Separate process | ✅ Same JVM, shared state |
| **HTTP API** | ❌ Not available | ✅ REST API |
| **Multi-client** | ⚠️ Sequential TCP | ✅ Concurrent (thread pool) |
| **GUI interop** | ❌ None | ✅ Same .jadx format |

---

## Migration Path

### Phase 1: ServerCore + ProjectManager (Backward Compatible)

1. Create `ServerCore` class — wraps JadxDecompiler + ProjectManager + DaemonCache
2. Create `ProjectManager` — load/save .jadx files
3. Create `CommandDispatcher` — unified command registry
4. Refactor `DaemonServer` to use `ServerCore` internally
   - Existing DaemonClient continues to work (same TCP protocol)
   - New: ProjectManager auto-saves on mutations
5. Refactor `JadxMcpServer` to use `ServerCore` internally
   - Existing MCP tools continue to work
   - New: 5 additional project tools

**This phase is 100% backward compatible.** CLI users see no change except:
- Renames and comments now survive daemon restarts
- `project summary` command is available

### Phase 2: Server Command + HTTP Transport

6. Create `ServerCommand` — `jadx-ai server start <apk>`
7. Create `HttpTransport` — REST API on port 17531
8. Add `--transport` flag: `tcp`, `mcp`, `http` (or combinations)
9. Add `--project` flag for explicit project path
10. Add `--auto-save` flag (on/off, default: on)

### Phase 3: Enhanced MCP + Missing Commands

11. Add missing MCP tools: jadx_cfg, jadx_signature, jadx_reload, jadx_script
12. Add project MCP tools: jadx_project_summary, jadx_bookmark, jadx_note, jadx_history, jadx_project_save
13. Add missing daemon commands: graph, hook, navigate (now automatically available via CommandDispatcher)
14. Split comment command into read/mutation halves for proper caching

### Phase 4: Advanced Features

15. WebSocket transport for real-time updates (analysis progress, new findings)
16. Concurrent request handling (thread pool for HTTP/TCP)
17. Live reload: watch APK file for changes, auto-reload
18. Event streaming: push events to connected clients (new note added, class renamed, etc.)
19. Multi-APK support: load multiple APKs in same server, switch between them

---

## ServerCommand Design

```java
@Command(name = "server", description = "Start the JADX analysis server with persistent project state",
         subcommands = { ServerStartCommand.class, ServerStopCommand.class, ServerStatusCommand.class })
public class ServerCommand extends AbstractCommand {
    @Override
    protected Object execute(JadxDecompiler decompiler) throws Exception {
        // Default: show server status
        return checkServerStatus();
    }
}

@Command(name = "start", description = "Start the JADX analysis server")
public class ServerStartCommand implements Runnable {

    @Parameters(index = "0", description = "Input file (APK, DEX, JAR, AAR)")
    File inputFile;

    @Option(names = {"--tcp-port"}, description = "TCP transport port", defaultValue = "17530")
    int tcpPort;

    @Option(names = {"--http-port"}, description = "HTTP transport port", defaultValue = "17531")
    int httpPort;

    @Option(names = {"--transport"}, description = "Enabled transports: tcp,mcp,http (comma-separated)", defaultValue = "tcp,mcp,http")
    String transports;

    @Option(names = {"--project"}, description = "Project file path (default: beside input file)")
    Path projectPath;

    @Option(names = {"--auto-save"}, description = "Auto-save project on mutations", defaultValue = "true")
    boolean autoSave;

    @Option(names = {"--background"}, description = "Run server in background")
    boolean background;

    @Option(names = {"--deobfuscation"}, description = "Enable deobfuscation")
    boolean deobfuscation;

    @Override
    public void run() {
        // 1. Resolve project path
        if (projectPath == null) {
            projectPath = resolveDefaultProjectPath(inputFile);
        }

        // 2. Create ServerCore
        JadxArgs args = buildJadxArgs();
        ServerCore core = new ServerCore();
        core.start(args, projectPath);

        // 3. Start transports
        EnumSet<TransportType> enabled = parseTransports(transports);
        if (enabled.contains(TCP))   new TcpTransport(core, tcpPort).start();
        if (enabled.contains(MCP))   new McpTransport(core).run();
        if (enabled.contains(HTTP))  new HttpTransport(core, httpPort).start();

        // 4. Keep alive until shutdown
        core.awaitShutdown();
        core.stop();
    }
}
```

---

## Summary: Why Server Mode Solves the Persistence Problem

| 问题 | Server Mode 解决方案 |
|------|---------------------|
| 重命名丢失 | rename → auto-save to .jadx → 下次启动自动加载 |
| 注释丢失 | comment add → auto-save to .jadx → 永久保留 |
| 搜索上下文丢失 | 每次搜索记录到 searchHistory → project summary 可查 |
| 分析笔记无存档 | note-add 带severity+tags → 结构化持久化 |
| 无书签机制 | bookmark-add 标记关键类 → 快速导航 |
| Daemon重启丢状态 | ServerCore.shutdown → project.save() → 重启加载 |
| AI Agent无上下文 | project summary → 一次调用获取全部分析历史 |
| MCP与Daemon不共享状态 | 统一ServerCore → 同一JVM、同一状态 |
| 无HTTP接口 | HTTP REST API → curl/浏览器/Python都能调用 |

**核心思想**：Server Mode 不是简单的"守护进程"，而是一个**持久化分析平台**。APK 加载一次，所有分析操作（搜索、反编译、重命名、注释、追踪、导出）都在同一个上下文中进行，状态自动保存，随时可以恢复。
