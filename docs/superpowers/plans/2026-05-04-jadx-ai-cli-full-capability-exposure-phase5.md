# JADX AI-CLI Phase 5: Code Reference Analysis & Position Resolution

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** 暴露 JADX 的代码引用关系分析能力和位置解析能力到 CLI，包括：位置→节点解析（getJavaNodeAtPosition/getClosestJavaNode/getEnclosingNode）、注解查询（getAnnotationAt）、修复 ClassDetailCommand 的 defPos/rawName 赋值缺失 bug。

**Architecture:** 增强 LineMapCommand 添加位置解析选项（--node-at/--closest-node/--enclosing-node），增强 UsageCommand 添加字段级别的 getUsed() 查询，修复 ClassDetailCommand 的字段赋值 bug。所有增强都基于现有命令，不新增命令。

**Tech Stack:** Java 21, picocli 4.7.5, Gson 2.10.1, JUnit 5, JADX core API

**Risks:**
- getJavaNodeAtPosition/getClosestJavaNode/getEnclosingNode 需要 ICodeInfo 参数，必须先调用 cls.getCodeInfo() 触发反编译 → 缓解：在调用前确保已获取 codeInfo
- 位置参数是字符偏移量（不是行号），用户可能混淆 → 缓解：在 CLI 描述中明确说明是 position（字符偏移）

---

### Task 1: Fix ClassDetailCommand defPos/rawName assignment bug

**Depends on:** None
**Files:**
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/ClassDetailCommand.java:68-91`

- [ ] **Step 1: 修复 MethodDetail 和 FieldDetail 的 defPos/rawName 赋值缺失**

文件: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/ClassDetailCommand.java:68-91`

替换 methods 循环和 fields 循环中的赋值代码：

```java
		detail.methods = new ArrayList<>();
		for (JavaMethod m : cls.getMethods()) {
			MethodDetail md = new MethodDetail();
			md.name = m.getName();
			md.returnType = m.getReturnType().toString();
			md.arguments = new ArrayList<>();
			for (jadx.core.dex.instructions.args.ArgType arg : m.getArguments()) {
				md.arguments.add(arg.toString());
			}
			md.isConstructor = m.isConstructor();
			md.isClassInit = m.isClassInit();
			md.accessFlags = m.getAccessFlags().rawValue();
			md.accessStr = m.getAccessFlags().toString();
			md.defPos = m.getDefPos();
			detail.methods.add(md);
		}

		detail.fields = new ArrayList<>();
		for (JavaField f : cls.getFields()) {
			FieldDetail fd = new FieldDetail();
			fd.name = f.getName();
			fd.rawName = f.getRawName();
			fd.type = f.getType().toString();
			fd.accessFlags = f.getAccessFlags().rawValue();
			fd.accessStr = f.getAccessFlags().toString();
			fd.defPos = f.getDefPos();
			detail.fields.add(fd);
		}
```

- [ ] **Step 2: 验证修复**
Run: `JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :jadx-ai-cli:spotlessApply :jadx-ai-cli:build`
Expected:
  - Exit code: 0
  - Output contains: "BUILD SUCCESSFUL"

- [ ] **Step 3: 提交**
Run: `git add jadx-ai-cli/src/main/java/jadx/ai/cli/commands/ClassDetailCommand.java && git commit -m "fix(jadx-ai-cli): assign defPos/rawName fields in ClassDetailCommand output"`

---

### Task 2: Add position-to-node resolution to LineMapCommand

**Depends on:** None
**Files:**
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/LineMapCommand.java`

- [ ] **Step 1: 添加 --node-at、--closest-node、--enclosing-node 选项到 LineMapCommand**

文件: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/LineMapCommand.java`

在现有 `--source-line` 选项后添加三个新选项：

```java
	@Option(names = { "--node-at" }, description = "Get JavaNode at exact position (character offset)")
	protected int nodeAtPos = -1;

	@Option(names = { "--closest-node" }, description = "Get closest JavaNode above position (character offset)")
	protected int closestNodePos = -1;

	@Option(names = { "--enclosing-node" }, description = "Get enclosing node (class/method) at position (character offset)")
	protected int enclosingNodePos = -1;
```

在 execute() 方法中，`return JsonOutput.ok(result);` 之前添加位置解析逻辑：

```java
			if (nodeAtPos >= 0) {
				JavaNode node = decompiler.getJavaNodeAtPosition(codeInfo, nodeAtPos);
				result.nodeAtPosition = buildNodeRef(node);
			}

			if (closestNodePos >= 0) {
				JavaNode node = decompiler.getClosestJavaNode(codeInfo, closestNodePos);
				result.closestNode = buildNodeRef(node);
			}

			if (enclosingNodePos >= 0) {
				JavaNode node = decompiler.getEnclosingNode(codeInfo, enclosingNodePos);
				result.enclosingNode = buildNodeRef(node);
			}
```

添加辅助方法和结果类：

```java
	private NodeRef buildNodeRef(JavaNode node) {
		if (node == null) {
			return null;
		}
		NodeRef ref = new NodeRef();
		ref.fullName = node.getFullName();
		ref.nodeType = getNodeType(node);
		ref.defPos = node.getDefPos();
		if (node.getDeclaringClass() != null) {
			ref.declaringClass = node.getDeclaringClass().getFullName();
		}
		return ref;
	}

	static class NodeRef {
		String fullName;
		String nodeType;
		int defPos;
		String declaringClass;
	}
```

在 LineMapResult 类中添加三个新字段：

```java
		NodeRef nodeAtPosition;
		NodeRef closestNode;
		NodeRef enclosingNode;
```

- [ ] **Step 2: 验证编译**
Run: `JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :jadx-ai-cli:spotlessApply :jadx-ai-cli:build`
Expected:
  - Exit code: 0
  - Output contains: "BUILD SUCCESSFUL"

- [ ] **Step 3: 提交**
Run: `git add jadx-ai-cli/src/main/java/jadx/ai/cli/commands/LineMapCommand.java && git commit -m "feat(jadx-ai-cli): add position-to-node resolution options to line-map command"`

---

### Task 3: Add annotation-at-position query to LineMapCommand

**Depends on:** Task 2
**Files:**
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/LineMapCommand.java`

- [ ] **Step 1: 添加 --annotation-at 选项到 LineMapCommand**

文件: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/LineMapCommand.java`

在 `--enclosing-node` 选项后添加：

```java
	@Option(names = { "--annotation-at" }, description = "Get code annotation at position (character offset)")
	protected int annotationAtPos = -1;
```

在 execute() 方法中，enclosing-node 逻辑之后添加：

```java
			if (annotationAtPos >= 0) {
				ICodeAnnotation ann = cls.getAnnotationAt(annotationAtPos);
				if (ann != null) {
					AnnotationAtResult annResult = new AnnotationAtResult();
					annResult.position = annotationAtPos;
					annResult.type = ann.getAnnType().name();
					JavaNode node = decompiler.getJavaNodeByCodeAnnotation(codeInfo, ann);
					if (node != null) {
						annResult.nodeFullName = node.getFullName();
						annResult.nodeType = getNodeType(node);
					}
					result.annotationAt = annResult;
				}
			}
```

添加结果类：

```java
	static class AnnotationAtResult {
		int position;
		String type;
		String nodeFullName;
		String nodeType;
	}
```

在 LineMapResult 类中添加字段：

```java
		AnnotationAtResult annotationAt;
```

- [ ] **Step 2: 验证编译**
Run: `JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :jadx-ai-cli:spotlessApply :jadx-ai-cli:build`
Expected:
  - Exit code: 0
  - Output contains: "BUILD SUCCESSFUL"

- [ ] **Step 3: 提交**
Run: `git add jadx-ai-cli/src/main/java/jadx/ai/cli/commands/LineMapCommand.java && git commit -m "feat(jadx-ai-cli): add --annotation-at option to line-map command"`

---

### Task 4: Add field-level getUsed() and class-level used query to UsageCommand

**Depends on:** None
**Files:**
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/UsageCommand.java`

- [ ] **Step 1: 增强 UsageCommand 的字段查询支持 getUsed()，并添加 class 级别的 used 查询**

文件: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/UsageCommand.java`

当前 `queryFieldUsage` 只支持 `getUseIn()`，需要添加 `getUsed()` 支持。修改 `queryFieldUsage` 方法：

```java
	private Object queryFieldUsage(JavaClass cls, String fldName) {
		cls.getCode();
		JavaField target = null;
		for (JavaField f : cls.getFields()) {
			if (f.getName().equals(fldName)) {
				target = f;
				break;
			}
		}
		if (target == null) {
			return JsonOutput.error("FieldNotFound", "Field not found: " + fldName);
		}
		List<UsageRef> refs = new ArrayList<>();
		for (JavaNode node : target.getUseIn()) {
			UsageRef ref = new UsageRef();
			ref.name = node.getFullName();
			ref.nodeType = getNodeType(node);
			refs.add(ref);
		}
		UsageResult result = new UsageResult();
		result.target = target.getFullName();
		result.targetType = "field";
		result.queryType = "useIn";
		result.references = refs;
		return JsonOutput.ok(result);
	}
```

同时增强 `queryClassUsage` 方法，添加 class 级别的 used 查询支持。当 queryType 为 "used" 时，遍历类的所有 methods 和 fields 收集它们 use 的节点：

```java
	private Object queryClassUsage(JavaClass cls) {
		cls.getCode();
		UsageResult result = new UsageResult();
		result.target = cls.getFullName();
		result.targetType = "class";

		if ("used".equals(queryType)) {
			result.queryType = "used";
			List<UsageRef> refs = new ArrayList<>();
			for (JavaMethod m : cls.getMethods()) {
				for (JavaNode node : m.getUsed()) {
					UsageRef ref = new UsageRef();
					ref.name = node.getFullName();
					ref.nodeType = getNodeType(node);
					refs.add(ref);
				}
			}
			result.references = refs;
		} else {
			result.queryType = "useIn";
			List<UsageRef> refs = new ArrayList<>();
			for (JavaNode node : cls.getUseIn()) {
				UsageRef ref = new UsageRef();
				ref.name = node.getFullName();
				ref.nodeType = getNodeType(node);
				refs.add(ref);
			}
			result.references = refs;
		}
		return JsonOutput.ok(result);
	}
```

- [ ] **Step 2: 验证编译**
Run: `JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :jadx-ai-cli:spotlessApply :jadx-ai-cli:build`
Expected:
  - Exit code: 0
  - Output contains: "BUILD SUCCESSFUL"

- [ ] **Step 3: 提交**
Run: `git add jadx-ai-cli/src/main/java/jadx/ai/cli/commands/UsageCommand.java && git commit -m "feat(jadx-ai-cli): add class-level used query and enhance field usage command"`

---

### Task 5: Add tests for Phase 5 features

**Depends on:** Task 1, Task 2, Task 3, Task 4
**Files:**
- Modify: `jadx-ai-cli/src/test/java/jadx/ai/cli/CommandsTest.java`

- [ ] **Step 1: 添加 Phase 5 测试方法**

文件: `jadx-ai-cli/src/test/java/jadx/ai/cli/CommandsTest.java`

在最后一个测试方法后添加：

```java
	@Test
	void testClassDetailDefPosAndRawName() {
		String output = runCommand("class-detail", "-c", "Hello", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\""), "Should contain success field: " + output);
		assertTrue(output.contains("\"defPos\""), "Should contain defPos: " + output);
		assertTrue(output.contains("\"rawName\""), "Should contain rawName: " + output);
	}

	@Test
	void testLineMapNodeAtPosition() {
		String output = runCommand("line-map", "-c", "Hello", "--node-at", "0", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\""), "Should contain success field: " + output);
		assertTrue(output.contains("\"nodeAtPosition\""), "Should contain nodeAtPosition: " + output);
	}

	@Test
	void testLineMapClosestNode() {
		String output = runCommand("line-map", "-c", "Hello", "--closest-node", "0", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\""), "Should contain success field: " + output);
		assertTrue(output.contains("\"closestNode\""), "Should contain closestNode: " + output);
	}

	@Test
	void testLineMapEnclosingNode() {
		String output = runCommand("line-map", "-c", "Hello", "--enclosing-node", "0", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\""), "Should contain success field: " + output);
		assertTrue(output.contains("\"enclosingNode\""), "Should contain enclosingNode: " + output);
	}

	@Test
	void testLineMapAnnotationAt() {
		String output = runCommand("line-map", "-c", "Hello", "--annotation-at", "0", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\""), "Should contain success field: " + output);
		assertTrue(output.contains("\"annotationAt\""), "Should contain annotationAt: " + output);
	}

	@Test
	void testUsageClassUsed() {
		String output = runCommand("usage", "-c", "Hello", "-t", "used", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\""), "Should contain success field: " + output);
		assertTrue(output.contains("\"used\""), "Should contain used queryType: " + output);
	}
```

- [ ] **Step 2: 验证测试通过**
Run: `JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :jadx-ai-cli:test`
Expected:
  - Exit code: 0
  - Output contains: "BUILD SUCCESSFUL"

- [ ] **Step 3: 提交**
Run: `git add jadx-ai-cli/src/test/java/jadx/ai/cli/CommandsTest.java && git commit -m "test(jadx-ai-cli): add tests for Phase 5 reference analysis and position resolution"`

---

### Task 6: Update skill docs for Phase 5 features

**Depends on:** Task 2, Task 3, Task 4
**Files:**
- Modify: `.claude/skills/jadx-line-map.md`
- Modify: `.claude/skills/jadx-search.md`

- [ ] **Step 1: 更新 jadx-line-map.md skill 文档**

文件: `.claude/skills/jadx-line-map.md`

在参数表中添加新选项：

| `--node-at` | No | Get JavaNode at exact position (character offset) |
| `--closest-node` | No | Get closest JavaNode above position (character offset) |
| `--enclosing-node` | No | Get enclosing node (class/method) at position (character offset) |
| `--annotation-at` | No | Get code annotation at position (character offset) |

在 Output Fields 中添加：

- nodeAtPosition: (with --node-at) {fullName, nodeType, defPos, declaringClass}
- closestNode: (with --closest-node) {fullName, nodeType, defPos, declaringClass}
- enclosingNode: (with --enclosing-node) {fullName, nodeType, defPos, declaringClass}
- annotationAt: (with --annotation-at) {position, type, nodeFullName, nodeType}

在 Examples 中添加：

```bash
# Get node at exact position
jadx-ai line-map -c com.example.MyClass --node-at 150 app.apk

# Get closest node above position
jadx-ai line-map -c com.example.MyClass --closest-node 150 app.apk

# Get enclosing class/method at position
jadx-ai line-map -c com.example.MyClass --enclosing-node 150 app.apk

# Get annotation at position
jadx-ai line-map -c com.example.MyClass --annotation-at 150 app.apk
```

- [ ] **Step 2: 创建 jadx-usage.md skill 文档**

文件: `.claude/skills/jadx-usage.md`

```markdown
---
name: jadx-usage
description: Query code reference relationships (call graph, cross-references) in Android APK/DEX files using JADX AI-CLI. Supports useIn (who references this) and used (what this references) queries for classes, methods, and fields.
---

# JADX Usage Skill

Query code reference relationships and cross-references in an Android APK/DEX file.

## Usage

When the user asks about code references, call graphs, who uses a class/method/field, or what a class/method uses:

1. Determine the target (class, method, or field) and query direction
2. Run the JADX AI-CLI usage command
3. Present the reference results

## Command

```bash
jadx-ai usage -c <class-name> [-m <method>] [-f <field>] [-t useIn|used] <input-file>
```

## Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `<input-file>` | Yes | Path to APK, DEX, JAR, AAR file |
| `-c, --class` | Yes | Class name to query |
| `-m, --method` | No | Method name (requires --class) |
| `-f, --field` | No | Field name (requires --class) |
| `-t, --type` | No | Query type: `useIn` (who uses this, default) or `used` (what this uses) |

## Query Types

| Type | Description | Available For |
|------|-------------|---------------|
| `useIn` | Who references/uses this node | Class, Method, Field |
| `used` | What this node references/uses | Class (via methods), Method |

## Output Fields

- target: full name of the queried node
- targetType: "class", "method", or "field"
- queryType: "useIn" or "used"
- references: list of {name, nodeType} referencing/referenced nodes
- overrideRelatedMethods: (method only) list of override-related method full names
- callsSelf: (method only) whether the method calls itself
- unresolvedUsed: (method only) list of unresolved method references

## Examples

```bash
# Who uses this class?
jadx-ai usage -c com.example.MyClass app.apk

# What does this class use?
jadx-ai usage -c com.example.MyClass -t used app.apk

# Who calls this method?
jadx-ai usage -c com.example.MyClass -m myMethod app.apk

# What methods does this method call?
jadx-ai usage -c com.example.MyClass -m myMethod -t used app.apk

# Who references this field?
jadx-ai usage -c com.example.MyClass -f myField app.apk
```
```

- [ ] **Step 3: 提交**
Run: `git add .claude/skills/jadx-line-map.md .claude/skills/jadx-usage.md && git commit -m "docs(jadx-ai-cli): update skill docs for Phase 5 reference analysis features"`
