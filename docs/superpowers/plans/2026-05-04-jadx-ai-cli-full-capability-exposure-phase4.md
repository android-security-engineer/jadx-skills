# jadx-ai-cli Phase 4: Complete Remaining API Capability Exposure

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** 暴露 JADX API 中所有剩余中高优先级未暴露的能力到 jadx-ai-cli，包括 8 个 JadxArgs 配置选项、JadxDecompiler 的 printErrorsReport/searchJavaClassOrItsParentByOrigFullName/getJavaNodeAtPosition/getEnclosingNode/save 方法，以及 JavaClass 的 getUsePlacesFor/getSourceLine 方法。

**Architecture:** 用户通过 CLI 选项 → AbstractCommand 映射到 JadxArgs → JadxDecompiler 使用配置反编译。增强现有命令的输出字段和选项，不创建新命令。LineMapCommand 增加 --use-places 和 --source-line 选项。InfoCommand 增加 errorsReport 字段。SearchCommand 增加 --search-parent 选项。ExportCommand 增加 --save-all 模式调用 decompiler.save()。

**Tech Stack:** Java 21, picocli 4.7.5, Gson 2.10.1, JADX core API, JUnit 5, Gradle 9.4.1

**Risks:**
- Task 1 修改 AbstractCommand 添加选项，影响所有命令 → 缓解：只添加新选项和 setter，不改现有默认值
- Task 2 修改 LineMapCommand/InfoCommand/SearchCommand/ExportCommand 输出结构 → 缓解：只添加新字段和选项，不删除或重命名现有字段
- Task 2 中 getUsePlacesFor 需要解析 node 引用 → 缓解：使用 class.method 或 class.field 格式解析

---

### Task 1: Add Remaining JadxArgs Configuration Options to AbstractCommand

**Depends on:** None
**Files:**
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/AbstractCommand.java:92-130`

- [ ] **Step 1: Add 8 remaining JadxArgs CLI options to AbstractCommand**

Add the following options after the existing `--use-dx-input` option (around line 129):

```java
	@Option(names = { "--user-renames-mappings-path" }, description = "Path to user renames mappings file")
	protected String userRenamesMappingsPath;

	@Option(names = { "--user-renames-mappings-mode" }, description = "User renames mappings mode: IGNORE, READ, READ_AND_APPLY, READ_APPLY_AND_SAVE", defaultValue = "IGNORE")
	protected String userRenamesMappingsMode = "IGNORE";

	@Option(names = { "--deobf-whitelist" }, description = "Deobfuscation whitelist (comma-separated class/package names ending with .*)")
	protected String deobfWhitelist;

	@Option(names = { "--export-gradle-type" }, description = "Export as Gradle project: AUTO, ANDROID, JAVA")
	protected String exportGradleType;

	@Option(names = { "--generated-renames-mapping-file" }, description = "Output file for generated renames mapping")
	protected String generatedRenamesMappingFile;

	@Option(names = { "--disabled-passes" }, description = "Disabled passes (comma-separated pass names)")
	protected String disabledPasses;

	@Option(names = { "--plugin-options" }, description = "Plugin options (key=value pairs, comma-separated)")
	protected String pluginOptionsStr;

	@Option(names = { "--disabled-plugins" }, description = "Disabled plugins (comma-separated plugin IDs)")
	protected String disabledPluginsStr;
```

- [ ] **Step 2: Add JadxArgs setter calls for new options in AbstractCommand.run() method**

Add the following lines after `args.setUseDxInput(useDxInput);` (around line 184):

```java
				if (userRenamesMappingsPath != null) {
					args.setUserRenamesMappingsPath(java.nio.file.Path.of(userRenamesMappingsPath));
					args.setUserRenamesMappingsMode(
							jadx.api.args.UserRenamesMappingsMode.valueOf(userRenamesMappingsMode.toUpperCase()));
				}
				if (deobfWhitelist != null) {
					args.setDeobfuscationWhitelist(
							java.util.Arrays.asList(deobfWhitelist.split(",")));
				}
				if (exportGradleType != null) {
					args.setExportGradleType(
							jadx.core.export.ExportGradleType.valueOf(exportGradleType.toUpperCase()));
				}
				if (generatedRenamesMappingFile != null) {
					args.setGeneratedRenamesMappingFile(new java.io.File(generatedRenamesMappingFile));
				}
				if (disabledPasses != null) {
					args.getDisabledPasses().addAll(java.util.Arrays.asList(disabledPasses.split(",")));
				}
				if (pluginOptionsStr != null) {
					java.util.Map<String, String> opts = new java.util.HashMap<>();
					for (String pair : pluginOptionsStr.split(",")) {
						String[] kv = pair.split("=", 2);
						if (kv.length == 2) {
							opts.put(kv[0], kv[1]);
						}
					}
					args.setPluginOptions(opts);
				}
				if (disabledPluginsStr != null) {
					args.setDisabledPlugins(new java.util.HashSet<>(java.util.Arrays.asList(disabledPluginsStr.split(","))));
				}
```

- [ ] **Step 3: Verify AbstractCommand compiles**
Run: `JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :jadx-ai-cli:spotlessApply :jadx-ai-cli:compileJava 2>&1 | tail -5`
Expected:
  - Exit code: 0
  - Output contains: "BUILD SUCCESSFUL"

- [ ] **Step 4: Commit**
Run: `git add jadx-ai-cli/src/main/java/jadx/ai/cli/commands/AbstractCommand.java && git commit -m "feat(jadx-ai-cli): add 8 remaining JadxArgs configuration options to CLI"`

---

### Task 2: Enhance Commands with Missing API Methods

**Depends on:** Task 1
**Files:**
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/LineMapCommand.java`
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/InfoCommand.java`
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/SearchCommand.java`
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/ExportCommand.java`

- [ ] **Step 1: Enhance LineMapCommand — add --use-places and --source-line options**

Add two new options to LineMapCommand:

```java
	@Option(names = { "--use-places" }, description = "Show use places for a specific node (format: class.method or class.field)")
	protected String usePlacesNode;

	@Option(names = { "--source-line" }, description = "Get source line for a specific decompiled line number")
	protected int sourceLine = -1;
```

Add to LineMapResult inner class: `List<Integer> usePlaces;` and `Integer sourceLineResult;`

Add logic after the usageMap block in execute():
```java
			if (usePlacesNode != null) {
				String[] parts = usePlacesNode.split("\\.", 2);
				jadx.api.JavaNode targetNode = null;
				if (parts.length == 2) {
					for (jadx.api.JavaMethod m : cls.getMethods()) {
						if (m.getName().equals(parts[1])) {
							targetNode = m;
							break;
						}
					}
					if (targetNode == null) {
						for (jadx.api.JavaField f : cls.getFields()) {
							if (f.getName().equals(parts[1])) {
								targetNode = f;
								break;
							}
						}
					}
				} else {
					targetNode = cls;
				}
				if (targetNode != null) {
					result.usePlaces = cls.getUsePlacesFor(codeInfo, targetNode);
				}
			}

			if (sourceLine != -1) {
				result.sourceLineResult = cls.getSourceLine(sourceLine);
			}
```

Add imports for `jadx.api.JavaMethod` and `jadx.api.JavaField` (already present).

- [ ] **Step 2: Enhance InfoCommand — add errorsReport field**

Add to ApkInfo inner class: `String errorsReport;`

Add assignment in execute() after warnsCount:
```java
			java.io.ByteArrayOutputStream errBaos = new java.io.ByteArrayOutputStream();
			java.io.PrintStream errPs = new java.io.PrintStream(errBaos);
			java.io.PrintStream oldErr = System.err;
			try {
				System.setErr(errPs);
				decompiler.printErrorsReport();
			} finally {
				System.setErr(oldErr);
			}
			info.errorsReport = errBaos.toString();
```

- [ ] **Step 3: Enhance SearchCommand — add --search-parent option for searchJavaClassOrItsParentByOrigFullName**

Add option:
```java
	@Option(names = { "--search-parent" }, description = "Search class or its parent if class has DONT_GENERATE flag")
	protected boolean searchParent;
```

Modify the class search logic: when `searchParent` is true, use `decompiler.searchJavaClassOrItsParentByOrigFullName(query)` instead of iterating getClasses(). Add a new case in the switch or modify searchClasses method.

Add to searchClasses method, at the beginning:
```java
		if (searchParent) {
			JavaClass cls = decompiler.searchJavaClassOrItsParentByOrigFullName(query);
			if (cls != null) {
				ClassSearchResult r = new ClassSearchResult();
				r.fullName = cls.getFullName();
				r.simpleName = cls.getName();
				r.packageName = cls.getPackage();
				results.add(r);
			}
			return JsonOutput.list(results);
		}
```

- [ ] **Step 4: Enhance ExportCommand — add --save-all mode for decompiler.save()**

Add option:
```java
	@Option(names = { "--save-all" }, description = "Use JADX save() to export all sources and resources to output dir")
	protected boolean saveAll;
```

Add logic at the beginning of execute(), before the existing loop:
```java
		if (saveAll) {
			decompiler.getArgs().setOutDir(outputDir);
			decompiler.getArgs().setOutDirSrc(new java.io.File(outputDir, "sources"));
			decompiler.getArgs().setOutDirRes(new java.io.File(outputDir, "resources"));
			decompiler.save();
			ExportSummary summary = new ExportSummary();
			summary.outputDir = outputDir.getAbsolutePath();
			summary.exportedCount = decompiler.getClasses().size();
			summary.errorCount = 0;
			return JsonOutput.ok(summary);
		}
```

- [ ] **Step 5: Verify enhanced commands compile**
Run: `JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :jadx-ai-cli:spotlessApply :jadx-ai-cli:compileJava 2>&1 | tail -5`
Expected:
  - Exit code: 0
  - Output contains: "BUILD SUCCESSFUL"

- [ ] **Step 6: Commit**
Run: `git add jadx-ai-cli/src/main/java/jadx/ai/cli/commands/LineMapCommand.java jadx-ai-cli/src/main/java/jadx/ai/cli/commands/InfoCommand.java jadx-ai-cli/src/main/java/jadx/ai/cli/commands/SearchCommand.java jadx-ai-cli/src/main/java/jadx/ai/cli/commands/ExportCommand.java && git commit -m "feat(jadx-ai-cli): enhance commands with remaining API methods (use-places, source-line, errors-report, search-parent, save-all)"`

---

### Task 3: Add Tests and Update Skill Documentation

**Depends on:** Task 2
**Files:**
- Modify: `jadx-ai-cli/src/test/java/jadx/ai/cli/CommandsTest.java`
- Modify: `.claude/skills/jadx-line-map.md`
- Modify: `.claude/skills/jadx-info.md`
- Modify: `.claude/skills/jadx-search.md`
- Modify: `.claude/skills/jadx-export.md`

- [ ] **Step 1: Add new test methods to CommandsTest.java**

Add test methods:
- `testLineMapWithUsePlaces()` — run `line-map -c Hello --use-places Hello.main` and assert contains `"usePlaces"`
- `testLineMapWithSourceLine()` — run `line-map -c Hello --source-line 1` and assert contains `"sourceLineResult"`
- `testInfoWithErrorsReport()` — run `info` and assert contains `"errorsReport"`
- `testSearchWithParent()` — run `search -t class -q Hello --search-parent` and assert contains `"success"`

- [ ] **Step 2: Update skill documentation files**

Update `.claude/skills/jadx-line-map.md` — add --use-places and --source-line options.
Update `.claude/skills/jadx-info.md` — add errorsReport to output fields.
Update `.claude/skills/jadx-search.md` — add --search-parent option.
Update `.claude/skills/jadx-export.md` — add --save-all option.

- [ ] **Step 3: Run full build and all tests**
Run: `JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :jadx-ai-cli:spotlessApply :jadx-ai-cli:build 2>&1 | tail -10`
Expected:
  - Exit code: 0
  - Output contains: "BUILD SUCCESSFUL"

- [ ] **Step 4: Commit**
Run: `git add jadx-ai-cli/src/test/java/jadx/ai/cli/CommandsTest.java .claude/skills/ && git commit -m "feat(jadx-ai-cli): add tests and skill docs for Phase 4 API exposure"`

---

### Task 4: Final Verification and API Coverage Report

**Depends on:** Task 3
**Files:**
- None (verification only)

- [ ] **Step 1: Verify CLI help shows all 11 commands**
Run: `JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :jadx-ai-cli:run --args="--help" 2>&1 | grep -c "class-detail\|decompile\|search\|usage\|list\|export\|info\|resources\|script\|package-detail\|line-map"`
Expected:
  - Count is 11

- [ ] **Step 2: Verify all tests pass**
Run: `JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :jadx-ai-cli:test 2>&1 | tail -5`
Expected:
  - Exit code: 0
  - Output contains: "BUILD SUCCESSFUL"

- [ ] **Step 3: Verify new options appear in command help**
Run: `JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :jadx-ai-cli:run --args="line-map --help" 2>&1 | grep -c "use-places\|source-line"`
Expected:
  - Count is 2
