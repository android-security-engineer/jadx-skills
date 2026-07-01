# Design: `jadx-ai-gui` — a companion JADX GUI plugin

**Question answered:** *Can we extend our tool with the live-GUI capability that
`zinja-coder/jadx-ai-mcp` has?* → **Yes — and with a structurally better design than
theirs,** because we own the whole jadx monorepo and already have a decoupled command
layer. This doc proves feasibility against the real APIs in this tree and lays out the plan.

---

## 1. Why we're well-positioned (verified facts)

- This repo **is the full jadx monorepo**: `jadx-core`, `jadx-gui`, `jadx-cli`,
  `jadx-ai-cli` are all source modules (`settings.gradle.kts`). zinja-coder built
  against an external jadx jar; we have compile-time access to `MainWindow` etc.
- The GUI plugin SPI exists and gives us everything their plugin uses:
  - `JadxPlugin` + `JadxPluginContext.getGuiContext()` → `JadxGuiContext`
    (`jadx-core/.../api/plugins/gui/JadxGuiContext.java`), which exposes:
    `getMainFrame()`, `addMenuAction(name, action)`, `addPopupMenuAction(...)`,
    `addTreePopupMenuEntry(...)`, `uiRun(Runnable)` (EDT-safe),
    `applyNodeRename(node)`, `reloadActiveTab()`, `copyToClipboard(...)`.
  - `MainWindow` (`jadx-gui/.../ui/MainWindow.java`) exposes `getWrapper()`,
    `getTabbedPane()`, `getDebuggerPanel()`, `events()`.
  - `JadxWrapper` exposes `getIncludedClassesWithInners()` and **`getDecompiler()`**.

- **The key lever — our command layer is already decoupled from decompiler creation.**
  `ServerCommandDispatcher.dispatch(command, args, session)` pulls
  `JadxDecompiler decompiler = session.getDecompiler()` and every one of the 24
  handlers operates purely on that `JadxDecompiler`. In the GUI,
  `MainWindow.getWrapper().getDecompiler()` returns **the same `JadxDecompiler` type**.

  ⇒ If we feed the GUI's *live* decompiler into our existing dispatcher, **all 24
  commands work in-GUI with zero per-command rewrites.** This is the decisive advantage:
  zinja-coder reimplemented ~35 endpoints by hand; we reuse one dispatcher.

---

## 2. Target architecture

```
                       ┌──────────────────────────── one shared command layer ───────────────────────────┐
 headless:  CLI / daemon / `server` ──► ServerCore ──► ServerCommandDispatcher ──► 24 handlers(JadxDecompiler)
                                                                  ▲
 in-GUI:    jadx-ai-gui plugin ──► PluginServer (Javalin/native) ─┘   + GUI-only handlers (live state)
              └─ feeds the GUI's live JadxDecompiler into the SAME dispatcher
```

Two "front doors," one brain. The GUI plugin is a **thin adapter** that:
1. Obtains the live `JadxDecompiler` from `MainWindow.getWrapper().getDecompiler()`.
2. Wraps it in an `AnalysisSession` (non-owning — see §3).
3. Routes inbound requests (HTTP/MCP/TCP — reuse our transports) to
   `ServerCore.executeCommand(...)`, which already handles caching + read-only checks.
4. Adds a small set of **GUI-only** handlers the headless side structurally cannot do.

---

## 3. The one required refactor

`AnalysisSession` currently *owns* its decompiler:

```java
public AnalysisSession(String sessionId, String inputPath, JadxArgs jadxArgs) throws Exception {
    this.decompiler = new JadxDecompiler(jadxArgs);
    this.decompiler.load();
    ...
}
public void close() { decompiler.close(); ... }   // would kill the GUI's decompiler!
```

Add a **non-owning** constructor + ownership flag so a GUI-provided decompiler isn't
created or closed by us:

```java
private final boolean ownsDecompiler;

// existing constructor: ownsDecompiler = true
// new constructor for GUI:
public AnalysisSession(String sessionId, String inputPath, JadxDecompiler external) {
    this.decompiler = external;          // already loaded by the GUI
    this.ownsDecompiler = false;
    this.cache = new DaemonCache(...);
    ...
}
public void close() {
    if (ownsDecompiler) { try { decompiler.close(); } catch (Exception ignored) {} }
    cache.invalidateAll();
}
```

That's the *only* change to existing code. Everything else is additive.

---

## 4. New module `jadx-ai-gui` (additive)

```
jadx-ai-gui/
  build.gradle.kts                       # depends on jadx-gui, jadx-core, jadx-ai-cli
  src/main/resources/META-INF/services/
      jadx.api.plugins.JadxPlugin        # → jadx.ai.gui.JadxAiGuiPlugin
  src/main/java/jadx/ai/gui/
      JadxAiGuiPlugin.java               # implements JadxPlugin; init() guards getGuiContext()==null
      GuiServer.java                     # transport; delegates to shared ServerCore
      GuiSessionAdapter.java             # wraps MainWindow.getWrapper().getDecompiler() in non-owning AnalysisSession
      GuiOnlyHandlers.java               # the live-state endpoints below
      GuiMenu.java                       # addMenuAction: Start/Stop/Port/Status
```

Register in `settings.gradle.kts`: `include("jadx-ai-gui")`.

### GUI-only handlers (the actual new capability)
These need a running GUI and can't exist headlessly — they are the reason to build this:
- `current-class` — code of the active tab (`getTabbedPane().getSelectedComponent()`).
- `selected-text` — analyst's current selection (live human-in-the-loop context).
- `live-rename` — mutate via `mainWindow.events().send(new NodeRenamedByUser(...))` so the
  GUI updates in place (vs. our headless `.jadx` mappings persistence).
- `debugger/*` — stack-frames / variables / threads from `getDebuggerPanel()` when a
  debug session is attached & suspended.

All other endpoints (search, list, decompile, usage/xrefs, resources, hook, navigate,
cfg, signature, comment, export, …) are served by the **existing** dispatcher.

---

## 5. Thread-safety note (important)

JADX GUI mutates decompiler/UI state on the **EDT**. Our server handlers run on
transport worker threads. For any handler touching live GUI/decompiler state, marshal
through `JadxGuiContext.uiRun(...)` (or `SwingUtilities.invokeAndWait`) — this is the
same lesson zinja-coder documents as their "EDT pattern." Read-only decompile calls on
already-processed classes are generally safe; renames and tab reads must go through EDT.

---

## 6. Effort & sequencing

1. (small) Refactor `AnalysisSession` for non-owning decompiler. ✅ unblocks reuse.
2. (small) New gradle module + plugin skeleton + `META-INF/services` registration.
3. (small) `GuiSessionAdapter` → run the existing dispatcher against the live decompiler;
   verify e.g. `search`, `decompile`, `usage` work in-GUI.
4. (medium) Add the 4 GUI-only handler groups + EDT marshalling.
5. (small) `GuiMenu` for start/stop/port + status, mirroring our daemon UX.
6. (optional) Share transports with `ServerCore` so MCP clients can target the in-GUI
   instance identically to the headless one.

**Net:** mostly additive; one tiny refactor to existing code; all 24 commands reused.
Conclusion: not only *can* we add GUI capability — our architecture makes it cheaper
for us than it was for the project we studied.
