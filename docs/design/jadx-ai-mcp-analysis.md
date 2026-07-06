# Competitive Analysis: `zinja-coder/jadx-ai-mcp`

Study of the upstream **jadx-ai-mcp** project (cloned 2026-06-24) and what we can
borrow into **jadx-ai-cli**. Source studied: full Java plugin at
`github.com/zinja-coder/jadx-ai-mcp` (the Python `jadx-mcp-server` bridge lives in a
sibling repo and was inferred from docs).

---

## 1. Their architecture (and how it differs from ours)

```
LLM client  ──MCP/stdio──►  jadx-mcp-server (Python, FastMCP)  ──HTTP/127.0.0.1:8650──►  JADX-GUI plugin (Java, Javalin) ──► JADX API + live GUI
```

- **It is a JADX *GUI plugin***, not a standalone tool. It loads inside the running
  JADX GUI (`init(JadxPluginContext)` returns early if `getGuiContext()==null`),
  grabs the `MainWindow`, and starts an embedded **Javalin** HTTP server bound to
  `127.0.0.1:8650`.
- **Two processes:** a Python FastMCP server translates MCP JSON-RPC ⇄ HTTP GET
  calls against the plugin. ~35 REST endpoints.
- **Delayed startup:** a scheduler polls every 1 s (2 s initial delay, 30 s
  fallback) until `JadxWrapper.getIncludedClassesWithInners()` is non-empty, then
  starts the server — because the plugin can load before the APK finishes decompiling.

### Contrast with our `jadx-ai-cli`

| | jadx-ai-mcp (theirs) | jadx-ai-cli (ours) |
|---|---|---|
| Runtime | Inside JADX **GUI** process | **Headless** CLI / daemon / server |
| MCP | Python FastMCP **bridge** → HTTP | **Native Java** MCP (stdio), no Python |
| Transports | HTTP only (Javalin) | TCP + MCP + HTTP (ServerCore) |
| Persistence | Java Preferences (port only) | `.jadx` project context (notes/bookmarks/history) |
| Unique strength | **Live GUI state** (current tab, selection, debugger) | **Automation / CI / scripting**, no GUI or Python needed |

**Strategic takeaway:** the two designs are complementary, not competing. Our native
Java MCP + headless model is a genuine deploy advantage (no Python, runs in CI). Their
unique advantage is *live human-in-the-loop GUI state*, which we structurally cannot
replicate headlessly. If we ever want that, it would be a **separate companion GUI
plugin**, not a change to the CLI.

---

## 2. Capabilities worth copying (ranked)

### HIGH — fills a known gap or solves a real pain

1. **`PaginationUtils` (generic offset/limit pagination).**
   Their `utils/PaginationUtils.java` is a clean, drop-in generic paginator: parses
   `offset`/`limit` (+ legacy `count`), validates bounds (MAX_OFFSET 1e6, MAX_PAGE
   10000, default 100), and returns rich metadata (`total`, `has_more`,
   `next_offset`, `prev_offset`, `current_page`, `total_pages`). Directly solves the
   "10k-class APK → 10 MB JSON → LLM client timeout" failure they document. Our
   `list`/`search`/`usage` commands should adopt this for every list-returning path.

2. **Multi-location search (`search_in = class|method|field|code|comment`).**
   `ClassRoutes.handleSearchClassesByKeyword` searches across selectable locations,
   dedups via `LinkedHashSet`, and **skips package filtering for obfuscated packages**
   (`^p\d+$`). This is exactly our recorded gap "SearchCommand needs code and comment
   search types." Borrow the enum + `search_in` parsing + dedup logic.

3. **`DecompilationCache` (compressed, concurrent, observable).**
   `ConcurrentHashMap<String,byte[]>` storing Deflate-level-1 compressed source per
   class, with hit/miss/ratio counters and `/cache-stats` + `/cache-clear`. For our
   **daemon/server** (warm JVM, repeated queries on the same APK) this is a large
   memory + latency win — we currently re-decompile. Add to `ServerCore`/`AnalysisSession`.

4. **`main-application-classes` triage (code + names).**
   Filters all classes by the **manifest package prefix** to return "the app's own
   classes, not the bundled libraries." Excellent first-look triage for an LLM. We
   have `navigate` (entry points) but not a "first-party classes only" view. Cheap to add.

### MEDIUM-HIGH — capability refinements

5. **Variable rename via SSA (`rename-variable`).**
   `RefactoringRoutes.handleRenameVariable` renames a local by walking
   `MethodNode.getSVars()`, and — when SSA is empty — forces processing
   (`unload()` + `forceProcess()` + re-fetch `MethodNode`), then targets the var by
   name/`reg`/`ssa`. Our `RenameCommand` covers class/method/field; variable rename is
   a real addition. Note the unload/reprocess pattern.

6. **xrefs that include constructors + override hierarchy.**
   `XrefsRoutes` adds constructor instantiation sites to class xrefs and follows
   `getOverrideRelatedMethods()` for method xrefs (polymorphic call sites). Our
   `usage`/`UsageCommand` (getUseIn/getUsed) likely misses these — worth folding in.

7. **Bulk `rename-package`.** Renames every class under a package prefix in one call,
   reporting `renamed`/`total`/`errors`. Convenient for deobfuscation workflows.

### MEDIUM — nice-to-have

8. **`SearchProgressTracker` + `/search-progress`.** Thread-safe singleton exposing
   live `scanned/total/matches/elapsed_ms` for long searches, with a 15-min stale
   flag. Useful in server mode so an LLM can poll a long-running search instead of
   blocking. (Single-active-search limitation is acceptable.)

9. **Rename mechanism via events.** They mutate names by sending
   `NodeRenamedByUser` through `mainWindow.events().send(...)` so the GUI updates
   live. We have no GUI; our `.jadx` mappings persistence is the headless equivalent —
   no change needed, just note the difference.

### DO NOT copy (GUI-only or inferior to what we have)

- **Live GUI endpoints** (`/current-class`, `/selected-text`, `/debug/*` stack-frames/
  variables/threads via reflection into `JDebuggerPanel`) — require a running GUI +
  attached debugger. Out of scope for headless CLI.
- **Cross-classloader socket-cleanup trick** & **EDT `invokeLater` discipline** —
  artifacts of living inside the GUI/Jetty. Not applicable. (But the general lesson —
  *guard shared decompiler state under the server's thread pool* — does apply to our
  multi-transport ServerCore.)
- **Python FastMCP bridge** — our native Java MCP is simpler to ship. Skip.

---

## 3. Security note to match

Their plugin binds **only `127.0.0.1`** and has **no auth** (relies on OS user
isolation); README explicitly warns that binding `0.0.0.0` lets *anyone on the
network* invoke every tool (including renames/mutations). Our HTTP/TCP transports
should **default to `127.0.0.1`** and require an explicit opt-in flag for any other bind
address. Verify `JadxServer`/`ServerCore` honor this.

---

## 4. Concrete adoption checklist

- [ ] Add a generic `PaginationUtils` to jadx-ai-cli; wire into `list`, `search`,
      `usage`, resource listing, and the server/MCP list tools.
- [ ] Extend `SearchCommand` with `--in class,method,field,code,comment` (+ obfuscated-
      package skip + dedup).
- [ ] Add a compressed `DecompilationCache` to `AnalysisSession`/`ServerCore`; expose
      `cache-stats` / `cache-clear` in server + MCP.
- [ ] Add `list --app-only` (manifest-package filter) for first-party triage.
- [ ] Add variable rename (SSA) to `RenameCommand`; add bulk package rename.
- [ ] Enrich `usage`/xrefs with constructor sites + override-related methods.
- [ ] (Server mode) optional `SearchProgressTracker` + poll endpoint.
- [ ] Confirm 127.0.0.1 default bind on all transports; gate non-local bind behind a flag.
- [ ] (Strategic, optional) evaluate a companion **JADX GUI plugin** to capture the
      live-state niche (current class / selection / debugger) we can't do headlessly.
