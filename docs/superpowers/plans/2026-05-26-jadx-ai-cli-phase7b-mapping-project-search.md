# JADX-AI-CLI Phase 7B: Mapping, Project, Search Enhancements + Integration

> Steps use checkbox (`- [ ]`) syntax.

**Goal:** Complete GUI parity by adding mapping import/export, project save/load, and code/comment search enhancements.

**Architecture:** MappingCommand uses `MappingExporter` + `net.fabricmc.mappingio` for format support. ProjectCommand serializes `JadxCodeData` as `.jadx` JSON. SearchCommand adds `code` (regex full-text) and `comment` search types.

**Tech Stack:** Java 11+, Gson 2.10.1, `net.fabricmc:mapping-io:0.8.0` (via jadx-rename-mappings), JadxDecompiler API, picocli 4.7.5

**Scope:** Large | **Risk:** Medium | **Autonomy Level:** Full

**Risks:**
- MappingCommand needs `jadx-rename-mappings` plugin as dependency → must add project dependency
- ProjectCommand reuses `JadxCodeData` JSON serialization → no GUI dependency needed
- SearchCommand `code` type iterates all classes → may be slow for large APKs → mitigated: `--limit` with early termination

---

### Task 1: Create MappingsCommand — mapping import/export

**Depends on:** None
**Files:**
- Create: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/MappingsCommand.java`
- Modify: `jadx-ai-cli/build.gradle.kts` (add rename-mappings dependency)
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/JadxAICLI.java` (add subcommand)

- [ ] **Step 1: Add mapping dependency to build.gradle.kts**

Modify `jadx-ai-cli/build.gradle.kts`, add: `implementation(project(":jadx-plugins:jadx-rename-mappings"))`

- [ ] **Step 2: Create MappingsCommand with export/import/list-formats operations**

Create `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/MappingsCommand.java` with:
- `--type export|import|list-formats` (default: export)
- `--output` path for export, `--input` path for import
- `--format` PROGUARD/TINY/TINY2/ENIGMA/SRG/TSRG/TSRG2/PARCHMENT/MOJMAP (auto-detect from extension if not specified)
- `--inverted` flag for ProGuard inverted mode
- Export: `new MappingExporter(rootNode).exportMappings(outPath, codeData, format)`
- Import: set `jadxArgs.userRenamesMappingsPath` + plugin options + `READ_APPLY_AND_SAVE` mode + `decompiler.reloadCodeData()`
- List-formats: iterate `MappingFormat.values()` returning name + hasSingleFile

- [ ] **Step 3: Register MappingsCommand in JadxAICLI**

Add import and subcommand entry in `JadxAICLI.java`.

- [ ] **Step 4: Verify compilation**

Run: `cd /data/local/tmp/workspace/github/AI-jadx && ./gradlew :jadx-ai-cli:compileJava 2>&1 | tail -5`
Expected: Exit code 0, "BUILD SUCCESSFUL"

- [ ] **Step 5: Commit**

Run: `git add jadx-ai-cli/build.gradle.kts jadx-ai-cli/src/main/java/jadx/ai/cli/commands/MappingsCommand.java jadx-ai-cli/src/main/java/jadx/ai/cli/JadxAICLI.java && git commit -m "feat(jadx-ai-cli): add MappingsCommand for ProGuard/Tiny/Enigma import/export"`

---

### Task 2: Create ProjectCommand — save/load .jadx project files

**Depends on:** None
**Files:**
- Create: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/ProjectCommand.java`
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/JadxAICLI.java` (add subcommand)

- [ ] **Step 1: Create ProjectCommand with save/load/info operations**

Create `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/ProjectCommand.java` with:
- `--type save|load|info` (default: save)
- `--output` for save path (default: `<inputBasename>.jadx`)
- `--input` for load path
- Save: serialize `JadxCodeData` (comments+renames) + input files as JSON with Gson (using `InterfaceReplace` type adapters for `ICodeComment`, `ICodeRename`, `IJavaNodeRef`, `IJavaCodeRef` interfaces)
- Load: deserialize `.jadx` JSON → set `jadxArgs.setCodeData(codeData)` → `decompiler.reloadCodeData()`
- Info: report current comment/rename counts

- [ ] **Step 2: Register ProjectCommand in JadxAICLI**

Add import and subcommand entry.

- [ ] **Step 3: Verify compilation**

Run: `cd /data/local/tmp/workspace/github/AI-jadx && ./gradlew :jadx-ai-cli:compileJava 2>&1 | tail -5`
Expected: Exit code 0, "BUILD SUCCESSFUL"

- [ ] **Step 4: Commit**

Run: `git add jadx-ai-cli/src/main/java/jadx/ai/cli/commands/ProjectCommand.java jadx-ai-cli/src/main/java/jadx/ai/cli/JadxAICLI.java && git commit -m "feat(jadx-ai-cli): add ProjectCommand for .jadx project save/load"`

---

### Task 3: Enhance SearchCommand — add code and comment search types

**Depends on:** None
**Files:**
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/SearchCommand.java` (add `code` and `comment` search types)

- [ ] **Step 1: Add code search type to SearchCommand**

Modify `SearchCommand.java` switch statement to add `case "code":` that:
1. Iterates all classes from `decompiler.getClasses()`
2. For each class, calls `cls.getCode()` to get decompiled source
3. Searches the source text with the query (supports `--regex` and `--ignore-case`)
4. Returns matching class name + line number + matching line snippet
5. Respects `--limit` for early termination

- [ ] **Step 2: Add comment search type to SearchCommand**

Add `case "comment":` that:
1. Gets `JadxCodeData` from `jadxArgs.getCodeData()`
2. Iterates `codeData.getComments()`
3. Filters by `comment.getComment().contains(query)` (case-insensitive)
4. Returns matching comment entries with nodeRef, codeRef, comment text, and style

- [ ] **Step 3: Verify compilation**

Run: `cd /data/local/tmp/workspace/github/AI-jadx && ./gradlew :jadx-ai-cli:compileJava 2>&1 | tail -5`
Expected: Exit code 0, "BUILD SUCCESSFUL"

- [ ] **Step 4: Commit**

Run: `git add jadx-ai-cli/src/main/java/jadx/ai/cli/commands/SearchCommand.java && git commit -m "feat(jadx-ai-cli): add code and comment search types to SearchCommand"`

---

### Task 4: Register all new commands in Daemon + MCP + update isReadOnly

**Depends on:** Task 1, Task 2, Task 3
**Files:**
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/daemon/DaemonServer.java` (add mappings, project daemon commands)
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/mcp/McpCommandDispatcher.java` (add mappings, project tools)
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/mcp/McpToolDefinitions.java` (add tool definitions)

- [ ] **Step 1: Register mappings and project commands in DaemonServer**

Add to `buildRegistry()`:
```java
reg.register("mappings", args -> executeMappings(args));
reg.register("project", args -> executeProject(args));
```

Add execution methods following the same pattern as existing commands.

- [ ] **Step 2: Add jadx_mappings and jadx_project tools to MCP**

Add to `McpCommandDispatcher.dispatch()` switch and `McpToolDefinitions.getAll()`:
- `jadx_mappings`: params type, output/input, format, inverted
- `jadx_project`: params type, output/input

- [ ] **Step 3: Update isReadOnlyCommand in DaemonServer**

Add `"project"` to the non-readonly list (project save is a write operation). Mappings import is also non-readonly.

- [ ] **Step 4: Verify full compilation**

Run: `cd /data/local/tmp/workspace/github/AI-jadx && ./gradlew :jadx-ai-cli:compileJava 2>&1 | tail -5`
Expected: Exit code 0, "BUILD SUCCESSFUL"

- [ ] **Step 5: Commit**

Run: `git add jadx-ai-cli/ && git commit -m "feat(jadx-ai-cli): register mappings and project commands in daemon and MCP"`
