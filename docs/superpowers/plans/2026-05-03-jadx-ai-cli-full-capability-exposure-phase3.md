# jadx-ai-cli Phase 3: Full API Capability Exposure

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** 暴露 JADX API 中所有剩余未暴露的能力到 jadx-ai-cli，包括缺失的 JadxArgs 配置选项、JavaClass/JavaMethod/JavaField 的未暴露方法，以及修复 SearchCommand alias 搜索 bug。

**Architecture:** 用户通过 CLI 选项 → AbstractCommand 映射到 JadxArgs → JadxDecompiler 使用配置反编译。增强现有命令的输出字段，不创建新命令。修复 SearchCommand 的 alias case 未调用 searchByAlias 方法的 bug。

**Tech Stack:** Java 21, picocli 4.7.5, Gson 2.10.1, JADX core API, JUnit 5, Gradle 9.4.1

**Risks:**
- Task 1 修改 AbstractCommand 添加选项，影响所有命令 → 缓解：只添加新选项和 setter，不改现有默认值
- Task 2 修改 ClassDetailCommand/UsageCommand 输出结构 → 缓解：只添加新字段，不删除或重命名现有字段
- Task 3 修复 SearchCommand bug → 缓解：仅修复 switch case 路由，不改搜索逻辑

---

### Task 1: Add Missing JadxArgs Configuration Options to AbstractCommand

**Depends on:** None
**Files:**
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/AbstractCommand.java:28-92`

- [ ] **Step 1: Add 12 missing JadxArgs CLI options to AbstractCommand**

Add the following options after the existing `--include-dependencies` option (around line 91):

```java
	@Option(names = { "--insert-debug-lines" }, description = "Insert debug line numbers into code")
	protected boolean insertDebugLines;

	@Option(names = { "--allow-inline-kotlin-lambda" }, description = "Allow inline Kotlin lambda", defaultValue = "true")
	protected boolean allowInlineKotlinLambda = true;

	@Option(names = { "--restore-switch-over-string" }, description = "Restore switch over string", defaultValue = "true")
	protected boolean restoreSwitchOverString = true;

	@Option(names = { "--skip-xml-pretty-print" }, description = "Skip XML pretty printing")
	protected boolean skipXmlPrettyPrint;

	@Option(names = { "--rename-case-sensitive" }, description = "Rename case sensitive", defaultValue = "true")
	protected boolean renameCaseSensitive = true;

	@Option(names = { "--rename-valid" }, description = "Rename to valid identifiers", defaultValue = "true")
	protected boolean renameValid = true;

	@Option(names = { "--rename-printable" }, description = "Rename to printable names", defaultValue = "true")
	protected boolean renamePrintable = true;

	@Option(names = { "--use-source-name-as-alias" }, description = "Use source name as class name alias")
	protected String useSourceNameAsAlias;

	@Option(names = { "--source-name-repeat-limit" }, description = "Source name repeat limit", defaultValue = "10")
	protected int sourceNameRepeatLimit = 10;

	@Option(names = { "--resource-name-source" }, description = "Resource name source: AUTO, ORIG, DEOBF", defaultValue = "AUTO")
	protected String resourceNameSource = "AUTO";

	@Option(names = { "--use-kotlin-methods-for-var-names" }, description = "Use Kotlin methods for var names: DISABLE, APPLY, APPLY_AND_HIDE", defaultValue = "APPLY")
	protected String useKotlinMethodsForVarNames = "APPLY";

	@Option(names = { "--use-dx-input" }, description = "Use DX input instead of java-input")
	protected boolean useDxInput;
```

- [ ] **Step 2: Add JadxArgs setter calls for new options in AbstractCommand.run() method**

Add the following lines after `args.setIncludeDependencies(includeDependencies);` (around line 129):

```java
				args.setInsertDebugLines(insertDebugLines);
				args.setAllowInlineKotlinLambda(allowInlineKotlinLambda);
				args.setRestoreSwitchOverString(restoreSwitchOverString);
				args.setSkipXmlPrettyPrint(skipXmlPrettyPrint);
				args.setRenameCaseSensitive(renameCaseSensitive);
				args.setRenameValid(renameValid);
				args.setRenamePrintable(renamePrintable);
				if (useSourceNameAsAlias != null) {
					args.setUseSourceNameAsClassNameAlias(
							jadx.api.args.UseSourceNameAsClassNameAlias.valueOf(useSourceNameAsAlias.toUpperCase()));
				}
				args.setSourceNameRepeatLimit(sourceNameRepeatLimit);
				args.setResourceNameSource(
						jadx.api.args.ResourceNameSource.valueOf(resourceNameSource.toUpperCase()));
				args.setUseKotlinMethodsForVarNames(
						jadx.api.args.JadxArgs.UseKotlinMethodsForVarNames.valueOf(useKotlinMethodsForVarNames.toUpperCase()));
				args.setUseDxInput(useDxInput);
```

- [ ] **Step 3: Verify AbstractCommand compiles**
Run: `JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :jadx-ai-cli:spotlessApply :jadx-ai-cli:compileJava 2>&1 | tail -5`
Expected:
  - Exit code: 0
  - Output contains: "BUILD SUCCESSFUL"

- [ ] **Step 4: Commit**
Run: `git add jadx-ai-cli/src/main/java/jadx/ai/cli/commands/AbstractCommand.java && git commit -m "feat(jadx-ai-cli): add 12 missing JadxArgs configuration options to CLI"`

---

### Task 2: Enhance Command Output with Missing API Fields

**Depends on:** Task 1
**Files:**
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/ClassDetailCommand.java:67-127`
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/UsageCommand.java:74-157`
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/ListCommand.java:77-88`

- [ ] **Step 1: Enhance ClassDetailCommand — add rawName to FieldDetail, isClassInit+defPos to MethodDetail, defPos to FieldDetail**

Add to FieldDetail inner class: `String rawName;` and `int defPos;`
Add to MethodDetail inner class: `boolean isClassInit;` and `int defPos;`
Add assignments in the fields loop: `fd.rawName = f.getRawName();` and `fd.defPos = f.getDefPos();`
Add assignments in the methods loop: `md.isClassInit = m.isClassInit();` and `md.defPos = m.getDefPos();`

- [ ] **Step 2: Enhance UsageCommand — add unresolvedUsed to method usage result**

Add `List<String> unresolvedUsed;` field to UsageResult inner class.
Add assignment in queryMethodUsage after callsSelf:
```java
			result.unresolvedUsed = new ArrayList<>();
			for (jadx.api.plugins.input.data.IMethodRef ref : mth.getUnresolvedUsed()) {
				result.unresolvedUsed.add(ref.toString());
			}
```

- [ ] **Step 3: Enhance ListCommand — add --with-inners option for getClassesWithInners()**

Add `@Option(names = { "--with-inners" }, description = "Include inner classes in listing")` and `protected boolean withInners;`
In listClasses(), when `withInners` is true, use `decompiler.getClassesWithInners()` instead of `decompiler.getClasses()`.

- [ ] **Step 4: Verify enhanced commands compile**
Run: `JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :jadx-ai-cli:spotlessApply :jadx-ai-cli:compileJava 2>&1 | tail -5`
Expected:
  - Exit code: 0
  - Output contains: "BUILD SUCCESSFUL"

- [ ] **Step 5: Commit**
Run: `git add jadx-ai-cli/src/main/java/jadx/ai/cli/commands/ClassDetailCommand.java jadx-ai-cli/src/main/java/jadx/ai/cli/commands/UsageCommand.java jadx-ai-cli/src/main/java/jadx/ai/cli/commands/ListCommand.java && git commit -m "feat(jadx-ai-cli): enhance command outputs with missing API fields (rawName, isClassInit, defPos, unresolvedUsed, withInners)"`

---

### Task 3: Fix SearchCommand Alias Bug and Enhance LineMap

**Depends on:** Task 1
**Files:**
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/SearchCommand.java:32-44`
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/LineMapCommand.java:52-79`

- [ ] **Step 1: Fix SearchCommand — alias case not calling searchByAlias()**

The switch statement at line 32-44 has cases for class, method, field, string but the "alias" case is missing. Add `case "alias": return searchByAlias(decompiler);` before the default case.

- [ ] **Step 2: Enhance LineMapCommand — add usage-map and use-places options**

Add `@Option(names = { "--usage-map" }, description = "Include usage map (position -> node)")` and `protected boolean includeUsageMap;`
Add `@Option(names = { "--use-places" }, description = "Show use places for a specific node (class.method or class.field)")` and `protected String usePlacesNode;`
Add a `UsageMapEntry` inner class with `int position; String nodeFullName; String nodeType;`
When `includeUsageMap` is true, iterate `cls.getUsageMap()` and add entries to result.
When `usePlacesNode` is specified, resolve the node and call `cls.getUsePlacesFor(codeInfo, node)` to get positions.

- [ ] **Step 3: Verify fixes compile**
Run: `JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :jadx-ai-cli:spotlessApply :jadx-ai-cli:compileJava 2>&1 | tail -5`
Expected:
  - Exit code: 0
  - Output contains: "BUILD SUCCESSFUL"

- [ ] **Step 4: Commit**
Run: `git add jadx-ai-cli/src/main/java/jadx/ai/cli/commands/SearchCommand.java jadx-ai-cli/src/main/java/jadx/ai/cli/commands/LineMapCommand.java && git commit -m "fix(jadx-ai-cli): fix alias search case routing, enhance line-map with usage-map and use-places"`

---

### Task 4: Update Tests, Skills, and Final Verification

**Depends on:** Task 2, Task 3
**Files:**
- Modify: `jadx-ai-cli/src/test/java/jadx/ai/cli/CommandsTest.java`
- Modify: `.claude/skills/jadx-class-detail.md`
- Modify: `.claude/skills/jadx-usage.md`
- Modify: `.claude/skills/jadx-line-map.md`
- Modify: `.claude/skills/jadx-list.md`
- Modify: `.claude/skills/jadx-search.md`

- [ ] **Step 1: Update CommandsTest.java — add tests for new features**

Add test methods:
- `testClassDetailWithNewFields()` — assert output contains `"rawName"`, `"isClassInit"`, `"defPos"`
- `testUsageWithUnresolvedUsed()` — assert output contains `"unresolvedUsed"`
- `testSearchAlias()` — run `search -t alias -q HelloWorld` and assert success
- `testLineMapWithUsageMap()` — run `line-map -c Hello --usage-map` and assert contains `"usageMap"`

- [ ] **Step 2: Update skill documentation files**

Update `.claude/skills/jadx-class-detail.md` — add rawName, isClassInit, defPos to output fields.
Update `.claude/skills/jadx-usage.md` — add unresolvedUsed to output fields.
Update `.claude/skills/jadx-line-map.md` — add --usage-map and --use-places options.
Update `.claude/skills/jadx-list.md` — add --with-inners option.
Update `.claude/skills/jadx-search.md` — confirm alias type is documented.

- [ ] **Step 3: Run full build and all tests**
Run: `JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :jadx-ai-cli:spotlessApply :jadx-ai-cli:build 2>&1 | tail -10`
Expected:
  - Exit code: 0
  - Output contains: "BUILD SUCCESSFUL"

- [ ] **Step 4: Verify CLI help shows all 11 commands**
Run: `JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :jadx-ai-cli:run --args="--help" 2>&1 | grep -c "Command\|class-detail\|decompile\|search\|usage\|list\|export\|info\|resources\|script\|package-detail\|line-map"`
Expected:
  - Count includes all 11 command names

- [ ] **Step 5: Commit**
Run: `git add jadx-ai-cli/src/test/java/jadx/ai/cli/CommandsTest.java .claude/skills/ && git commit -m "feat(jadx-ai-cli): add tests and skill docs for Phase 3 API exposure"`
