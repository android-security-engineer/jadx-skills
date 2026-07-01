# JADX Skills Repository — Goal: Full Capability Exposure, API Docs & Workflows

This document captures our three interrelated goals and the current state of progress.

---

## Goal 1: 将 jadx 所有能力通过 CLI 透出

### Current CLI Command Coverage (jadx-ai-cli)

The `jadx-ai` CLI currently has **20 subcommands** registered:

| Command | CLI Name | Jadx API Used | Status |
|---------|----------|---------------|--------|
| DecompileCommand | `decompile` | JavaClass.getCode(), getCodeInfo(), getSmali() | ✅ Done |
| SearchCommand | `search` | ClassNode iteration, string/field/method search | ✅ Done |
| UsageCommand | `usage` | JavaNode.getUseIn(), getUsed() | ✅ Done |
| ListCommand | `list` | getClasses(), getPackages(), getMethods(), getFields() | ✅ Done |
| ExportCommand | `export` | decompiler.save(), saveSources(), saveResources() | ✅ Done |
| InfoCommand | `info` | getErrorsCount(), getWarnsCount(), printErrorsReport() | ✅ Done |
| ResourcesCommand | `resources` | getResources(), ResourceFile.loadContent() | ✅ Done |
| ScriptCommand | `script` | JadxDecompiler (via JS engine binding) | ✅ Done |
| PackageDetailCommand | `package-detail` | JavaPackage hierarchy | ✅ Done |
| LineMapCommand | `line-map` | ICodeInfo.getCodeMetadata(), line mapping, annotations | ✅ Done |
| RenameCommand | `rename` | IRenameNode.removeAlias(), ClassNode/MethodNode alias | ✅ Done |
| ReloadCommand | `reload` | JavaClass.reload(), unload(), reloadCodeData() | ✅ Done |
| GraphCommand | `graph` | UsageInfo (call/inheritance/usage graphs) | ✅ Done |
| HookCommand | `hook` | Method/Field signatures → Frida/Xposed template generation | ✅ Done |
| NavigateCommand | `navigate` | AndroidManifest parsing → entry points, activities | ✅ Done |
| CommentCommand | `comment` | ICodeComment, JadxCodeData | ✅ Done |
| CfgCommand | `cfg` | DotGraphUtils.dumpToString(), MethodNode internals | ✅ Done |
| SignatureCommand | `signature` | ApkVerifier (apksig library) | ✅ Done |
| DaemonCommand | `daemon` | Background JVM with persistent JadxDecompiler | ✅ Done |
| McpCommand | `mcp` | MCP Server (stdio JSON-RPC) | ✅ Done |

### AbstractCommand JadxArgs Options Coverage

AbstractCommand exposes **30+ JadxArgs configuration options** via CLI flags. Key ones:
- `--decompilation-mode`, `--show-bad-code`, `--deobfuscation`, `--comments-level`
- `--include-resources`, `--use-imports`, `--debug-info`, `--inline-anonymous`, `--inline-methods`
- `--move-inner`, `--extract-finally`, `--escape-unicode`, `--replace-consts`
- `--deobf-min-length`, `--deobf-max-length`, `--integer-format`, `--threads-count`
- `--class-filter`, `--include-dependencies`, `--insert-debug-lines`
- `--allow-inline-kotlin-lambda`, `--restore-switch-over-string`
- `--skip-xml-pretty-print`, `--rename-case-sensitive`, `--rename-valid`, `--rename-printable`
- `--use-source-name-as-alias`, `--source-name-repeat-limit`, `--resource-name-source`
- `--use-kotlin-methods-for-var-names`, `--use-dx-input`
- `--user-renames-mappings-path`, `--user-renames-mappings-mode`, `--deobf-whitelist`
- `--export-gradle-type`, `--generated-renames-mapping-file`
- `--disabled-passes`, `--plugin-options`, `--disabled-plugins`, `--security-flags`

### JadxArgs NOT Yet Exposed via CLI

These JadxArgs properties are NOT yet mapped to CLI options:

| Property | Type | Priority | Notes |
|----------|------|----------|-------|
| `outputFormat` (JAVA/JSON) | Enum | Low | CLI already outputs JSON |
| `codeNewLineStr` / `codeIndentStr` | String | Low | Formatting config, rarely needed |
| `typeUpdatesLimitCount` | int | Low | Internal tuning |
| `skipSources` / `skipFilesSave` | boolean | Medium | Useful for "only resources" mode |
| `useHeadersForDetectResourceExtensions` | boolean | Low | Edge case |
| `fsCaseSensitive` | boolean | Low | Platform-specific |
| `loadJadxClsSetFile` | boolean | Low | Internal |
| `runDebugChecks` | boolean | Low | Debug only |
| `codeCache` / `usageInfoCache` | Object | Skip | Not CLI-configurable |
| `codeWriterProvider` | Function | Skip | Not CLI-configurable |
| `aliasProvider` / `renameCondition` | Object | Skip | Plugin-level, not CLI |
| `codeData` | ICodeData | Skip | Plugin-level |
| `pluginLoader` | Object | Skip | Internal |

### JadxDecompiler Methods NOT Yet Exposed

| Method | Return | CLI Gap | Priority |
|--------|--------|---------|----------|
| `getClassesWithInners()` | List<JavaClass> | ListCommand has `--with-inners` | ✅ Covered |
| `getPackages()` | List<JavaPackage> | ListCommand | ✅ Covered |
| `searchJavaClassByOrigFullName()` | JavaClass | Multiple commands | ✅ Covered |
| `searchJavaClassByAliasFullName()` | JavaClass | SearchCommand alias | ✅ Covered |
| `searchJavaClassOrItsParentByOrigFullName()` | JavaClass | SearchCommand `--search-parent` | ✅ Covered |
| `getJavaNodeByRef()` | JavaNode | LineMap/Usage internals | ✅ Covered |
| `getJavaNodeAtPosition()` | JavaNode | LineMap `--node-at` | ✅ Covered |
| `getClosestJavaNode()` | JavaNode | LineMap `--closest-node` | ✅ Covered |
| `getEnclosingNode()` | JavaNode | LineMap `--enclosing-node` | ✅ Covered |
| `reloadCodeData()` | void | ReloadCommand `-t codedata` | ✅ Covered |
| `reloadPasses()` | void | **NOT COVERED** | Medium |
| `save()` / `saveSources()` / `saveResources()` | void | ExportCommand | ✅ Covered |
| `printErrorsReport()` | void | InfoCommand errorsReport | ✅ Covered |
| `addCustomCodeLoader()` | void | **NOT COVERED** | Low (plugin-level) |
| `addCustomResourcesLoader()` | void | **NOT COVERED** | Low (plugin-level) |
| `addCustomPass()` | void | **NOT COVERED** | Low (plugin-level) |
| `getVersion()` | String | InfoCommand | ✅ Covered |
| `getErrorsCount()` / `getWarnsCount()` | int | InfoCommand | ✅ Covered |
| `registerPlugin()` | void | **NOT COVERED** | Low (plugin-level) |
| `events()` / `setEventsImpl()` | IJadxEvents | **NOT COVERED** | Low |

### Remaining CLI Gaps (Action Items)

1. **MappingsCommand** — mapping import/export (from Phase 7B plan, not yet implemented)
   - Uses `MappingExporter` + `net.fabricmc.mappingio` for format support
   - Import/export ProGuard, Tiny, etc. mapping formats

2. **ProjectCommand** — project save/load for context persistence (**DESIGNED**, see `docs/design/persistent-context-design.md`)
   - Serializes analysis state as `.jadx` JSON compatible with GUI's JadxProject format
   - CLI-extended fields: analysisNotes, bookmarks, analysisLog, sessionState
   - Subcommands: init, status, bookmarks, notes, history, summary, save, reset
   - Core class: `ProjectManager` with auto-save on mutations

3. **reloadPasses()** — reload decompiler passes without re-loading APK (medium priority)

### SearchCommand Gaps (RESOLVED)

4. **SearchCommand: `code` type** — ✅ DONE (full-text regex search across all decompiled code)
5. **SearchCommand: `comment` type** — ✅ DONE (search across code comments in JadxCodeData)
6. **SearchCommand: `alias` type** — ✅ DONE (search by alias full name)

6. **Hex/Binary resource viewer** — GUI has hex viewer for binary resources, CLI doesn't

7. **Smali debugger** — GUI has smali debugger integration, CLI doesn't (very complex, low priority)

8. **Daemon command gaps** — graph, hook, navigate, comment(add/update/delete) NOT in DaemonServer.buildRegistry()
   - These work in local mode but bypass the daemon cache when daemon is running
   - FIX: Add executeGraph, executeHook, executeNavigate, executeComment to DaemonServer

9. **MCP tool gaps** — cfg, signature, reload, script NOT in McpToolDefinitions (15 of 20+ commands)
   - Need: jadx_cfg, jadx_signature, jadx_reload, jadx_script
   - Also need project tools: jadx_project_summary, jadx_bookmark, jadx_note, jadx_history, jadx_project_save

---

## Goal 2: API Documentation for AI Agents

### Target Audience
AI agents that need to write Java scripts/programs that depend on jadx JARs and call jadx APIs programmatically.

### Core API Classes to Document

| Package/Class | Purpose | Key Methods |
|---------------|---------|-------------|
| `jadx.api.JadxArgs` | Configuration | 50+ setters/getters for all decompilation options |
| `jadx.api.JadxDecompiler` | Main entry point | load(), save(), getClasses(), getResources(), search... |
| `jadx.api.JavaClass` | Decompiled class | getCode(), getCodeInfo(), getMethods(), getFields(), getUseIn()... |
| `jadx.api.JavaMethod` | Decompiled method | getName(), getArguments(), getReturnType(), getUseIn(), getUsed()... |
| `jadx.api.JavaField` | Decompiled field | getName(), getType(), getUseIn()... |
| `jadx.api.JavaPackage` | Package structure | getName(), getClasses(), getSubPackages()... |
| `jadx.api.JavaNode` | Base interface | getName(), getFullName(), getDeclaringClass(), getTopParentClass()... |
| `jadx.api.JavaVariable` | Local variable | getName(), getType()... |
| `jadx.api.ICodeInfo` | Code result | getCodeStr(), hasMetadata(), getCodeMetadata()... |
| `jadx.api.ICodeCache` | Code caching | InMemoryCodeCache, NoOpCodeCache |
| `jadx.api.ResourceFile` | APK resource | getName(), getType(), loadContent()... |
| `jadx.api.ResourceFileContent` | Resource content | getText(), getInputStream()... |
| `jadx.api.ResourcesLoader` | Resource loading | decodeStream(), loadContent()... |
| `jadx.api.data.ICodeComment` | Code comments | getNodeRef(), getComment(), getStyle()... |
| `jadx.api.data.ICodeRename` | Renames | getNodeRef(), getNewName()... |
| `jadx.api.data.ICodeData` | Code data container | getComments(), getRenames()... |
| `jadx.api.metadata.ICodeMetadata` | Code metadata | getAt(), getLineMapping(), searchDown()... |
| `jadx.api.metadata.ICodeAnnotation` | Annotations | getAnnType(), node refs |
| `jadx.api.plugins.JadxPlugin` | Plugin interface | init(), getPasses... |
| `jadx.api.plugins.JadxPluginContext` | Plugin context | registerPass(), registerCodeInput()... |
| `jadx.api.plugins.pass.JadxPass` | Custom pass | getInfo(), run()... |
| `jadx.api.security.IJadxSecurity` | Security checks | flags configuration |
| `jadx.api.usage.IUsageInfoCache` | Usage caching | getUseIn(), getUsed()... |
| `jadx.api.args.*` | Enum configs | DecompilationMode, CommentsLevel, IntegerFormat... |

### Documentation Plan

Need to create:
1. **`docs/api/JadxDecompiler-API.md`** — Main entry point, lifecycle, all public methods with signatures and examples
2. **`docs/api/JavaClass-API.md`** — Class inspection, decompilation, code access
3. **`docs/api/JavaMethod-JavaField-API.md`** — Method/field inspection, usage queries
4. **`docs/api/JadxArgs-API.md`** — Full configuration reference (all 50+ options)
5. **`docs/api/Resource-API.md`** — Resource access, content loading, binary XML parsing
6. **`docs/api/Metadata-API.md`** — Code metadata, annotations, position resolution
7. **`docs/api/Plugin-API.md`** — Plugin development, custom passes, code inputs
8. **`docs/api/Script-API.md`** — How to use ScriptCommand with JS engine
9. **`docs/api/Quick-Start.md`** — Minimal "hello world" example for AI agents
10. **`docs/api/Maven-Coordinates.md`** — How to add jadx as Maven/Gradle dependency

---

## Goal 3: Workflow Compositions

### What is a "workflow"?
A workflow composes multiple jadx CLI commands (or API calls) into a sequence that accomplishes a specific reverse-engineering task. Workflows should be:
- **Callable from CLI** (as skill files or composed bash scripts)
- **Callable from MCP** (as tool sequences)
- **Callable from Java API** (as programmatic method chains)
- **Callable from scripts** (via ScriptCommand or standalone Java programs)

### Proposed Workflow Catalog

#### Security Analysis Workflows

1. **apk-security-audit** — Full security audit of an APK
   - `info` → `signature` → `navigate entry-points` → `search string "http"` → `search method "encrypt"` → `search method "decrypt"` → `resources MANIFEST` → `search class "Cipher"` → `search class "WebView"` → `decompile` targets → `usage` trace crypto call chains → `hook` generate Frida snippets

2. **crypto-usage-analysis** — Find all crypto operations
   - `search class Cipher` → `search method encrypt` → `search method decrypt` → `search string "AES"` → `search string "RSA"` → `decompile` each → `usage` trace callers → `graph call` for crypto chain

3. **network-security-analysis** — Find network endpoints & API keys
   - `search string "http://" → `search string "https://" → `search string "api_key" → `search method "Retrofit" → `search method "OkHttp" → `decompile` network classes → `resources` for network_security_config.xml

4. **permission-risk-analysis** — Analyze dangerous permissions
   - `resources MANIFEST` → parse permissions → `search class "LocationManager"` → `search class "Camera"` → `search class "BluetoothAdapter"` → `decompile` permission-using classes → `usage` trace call chains

#### Reverse Engineering Workflows

5. **entry-point-discovery** — Find all app entry points
   - `navigate entry-points` → `navigate main-activity` → `navigate application` → `navigate manifest` → `decompile` each entry → `usage` trace from entry points

6. **class-hierarchy-analysis** — Understand class inheritance
   - `class-detail` → `graph inheritance` → `decompile` key classes → `usage` trace polymorphism

7. **method-call-chain** — Trace a method's full call graph
   - `search method` → `usage -t useIn --depth 3` → `usage -t used --depth 3` → `graph call --depth 5` → `decompile` chain methods

8. **deobfuscation-workflow** — Rename obfuscated identifiers
   - `info` (check class count) → `search class` (find obfuscated names) → `class-detail` (see methods) → `rename` (apply meaningful names) → `decompile` (verify) → `export` (save renamed code)

9. **string-constant-analysis** — Find all hardcoded strings
   - `search string "" --limit 500` → categorize (URLs, keys, paths, errors) → `decompile` containing classes → `usage` trace string usage

#### Integration & Export Workflows

10. **frida-hook-generation** — Generate Frida hooks for dynamic analysis
   - `navigate entry-points` → `search method` → `hook -t frida` → compose into Frida script

11. **xposed-module-skeleton** — Generate Xposed module code
   - `navigate entry-points` → `class-detail` → `hook -t xposed` → compose Xposed module

12. **full-export-workflow** — Complete export for offline analysis
   - `info` → `export --save-all` → `resources --content` → `signature` → `line-map` for key classes

#### Comparison Workflows

13. **apk-diff-analysis** — Compare two APK versions
   - `info` both → `list -t class` both → diff class lists → `decompile` changed classes → `usage` trace impact

14. **library-identification** — Identify third-party libraries
   - `list -t package` → filter known library packages → `class-detail` → `search string "version"` → identify library versions

---

## Implementation Priority

### Immediate (Next Steps)
1. ✅ Create comprehensive API documentation (Goal 2) — DONE: 4 docs created
2. ✅ Add `code`, `comment`, `alias` search types to SearchCommand (Goal 1 gap) — DONE
3. ✅ Create workflow skill files for the top 7 workflows (Goal 3) — DONE
4. **Implement ServerCore + ProjectManager** (Goal 4+5) — DESIGNED, see `docs/design/server-mode-design.md`
5. **Fix daemon command gaps** — add graph, hook, navigate, comment to DaemonServer.buildRegistry()
6. **Fix MCP tool gaps** — add jadx_cfg, jadx_signature, jadx_reload, jadx_script to McpToolDefinitions

### Medium Priority
7. Add `reloadPasses` to ReloadCommand (Goal 1 minor gap)
8. Document remaining API classes (Goal 2 continued: Resource-API, Metadata-API, Plugin-API)
9. Implement MappingsCommand (mapping import/export)
10. Add project MCP tools (jadx_project_summary, jadx_bookmark, jadx_note, jadx_history, jadx_project_save)
11. Create continuous-analysis workflow skill file

### Long-term
12. Binary/hex resource viewer for CLI
13. Smali debugger integration for CLI (very complex)
14. AI agent orchestration patterns (multi-agent workflows using MCP)

---

## Goal 4: Persistent Context for Continuous APK Analysis

**Full design:** `docs/design/persistent-context-design.md`

### Problem
When reverse-engineering an APK across multiple CLI invocations, all analysis state is lost:
- Renames, comments, search history, bookmarks — all disappear between calls
- Even the daemon holds everything in RAM — a restart kills all state
- AI agents must rebuild context from scratch each session

### Solution: `.jadx` Project Files with CLI Extensions
- Extend the GUI's existing `ProjectData` format with CLI-specific fields
- `ProjectManager` loads/saves `.jadx` files, auto-saves on mutations
- `ProjectCommand` exposes subcommands for state management
- `project summary` gives AI agents full context in a single call
- Daemon integration: project loads on start, saves on mutations and shutdown

### Key Components
| Component | Purpose |
|-----------|---------|
| `ProjectManager` | Load/save project files, manage state lifecycle |
| `ProjectData` (CLI-extended) | Data model extending GUI's format |
| `AnalysisNote` | Structured findings with severity + tags |
| `Bookmark` | Labeled references to classes/methods of interest |
| `AnalysisLogEntry` | Audit trail of all commands executed |
| `SessionState` | Resume context: lastViewedClass, analysisPhase |
| `ProjectCommand` | CLI subcommands for project management |
| 5 new MCP tools | Project state management for AI agents |

### Implementation Phases
1. **Core**: ProjectManager + ProjectData + AbstractCommand integration
2. **Command**: ProjectCommand with subcommands
3. **MCP**: 5 new tool definitions + dispatcher methods
4. **Workflow**: Update skills to use `project summary` at session start

---

## Goal 5: Unified Server Mode

**Full design:** `docs/design/server-mode-design.md`

### Problem
当前 DaemonServer 和 MCP Server 是两个独立实现，各自都有严重局限：
- DaemonServer: 16个命令、纯内存（重启丢状态）、无项目持久化
- MCP Server: 每次启动重新加载APK、MCP断连即丢状态
- 两者不共享状态：MCP 看不到 Daemon 的重命名/注释

### Solution: Unified Server with Multi-Transport

一个 `jadx-ai server start <apk>` 命令启动统一服务器，支持三种传输协议：
- **TCP** (port 17530) — CLI 客户端自动检测（现有 DaemonClient 无需修改）
- **MCP** (stdio JSON-RPC) — AI Agent 集成（Claude Desktop / Cursor）
- **HTTP** (port 17531) — REST API（curl / 浏览器 / Python）

### Architecture: ServerCore as Single Source of Truth

```
所有 Transport → ServerCore → CommandDispatcher → Command Handlers
                      ↓
              ProjectManager → .jadx Project File
                      ↓
              JadxDecompiler (in-memory)
                      ↓
              DaemonCache (TTL)
```

### Key Innovation: ServerCore owns ProjectManager
- **Every mutation command auto-saves** to .jadx project file
- **Read-only commands check cache** before execution
- **Server shutdown guarantees save** via shutdown hook
- **All transports share same state** — no more Daemon/MCP split

### New Components
| Component | Purpose |
|-----------|---------|
| `ServerCore` | Unified command processing core |
| `CommandDispatcher` | All 30+ commands in one registry |
| `ServerCommand` | CLI: `jadx-ai server start/stop/status` |
| `TcpTransport` | Existing daemon protocol (backward compatible) |
| `McpTransport` | JSON-RPC 2.0 over stdio |
| `HttpTransport` | REST API for web/curl integration |

### Migration Path
1. **Phase 1** (backward compatible): ServerCore + ProjectManager, refactor DaemonServer/McpServer to use it
2. **Phase 2**: ServerCommand + HTTP transport + --transport/--project flags
3. **Phase 3**: Enhanced MCP (missing tools), missing daemon commands
4. **Phase 4**: WebSocket, concurrent requests, live reload, event streaming

### How This Enables Persistent Analysis

```bash
# Session 1: Start server, analyze, auto-save
jadx-ai server start app.apk --background
jadx-ai rename -t class -c "com.a" -n "LoginActivity" app.apk   # → auto-saved
jadx-ai daemon stop app.apk                                        # → project saved

# Session 2: Resume — all renames/comments/notes restored
jadx-ai server start app.apk --background
jadx-ai project summary app.apk  # → shows all context from Session 1
jadx-ai decompile -c com.app.LoginActivity app.apk  # → rename already applied
```
