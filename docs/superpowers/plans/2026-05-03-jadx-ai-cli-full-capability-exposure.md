# jadx-ai-cli Full Capability Exposure Plan

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** 将 jadx 反编译器的所有核心能力通过 AI 友好的 CLI 命令暴露出去，包括资源访问、使用关系图、类继承详情、方法签名、错误报告、反混淆配置等，并编写对应的 Claude Code Skills。

**Architecture:** APK/DEX 输入 → JadxDecompiler 加载 → 各子命令通过 `execute(decompiler)` 访问 API → JsonOutput 封装结构化 JSON 输出。新增 3 个命令（resources/usage/class-detail）覆盖未暴露能力，增强 3 个现有命令（info/list/search）补充缺失信息，增强 AbstractCommand 支持反编译配置选项。

**Tech Stack:** Java 21, picocli 4.7.5, Gson 2.10.1, jadx-core (local), JUnit 5.10.1, Gradle 9.4.1

**Risks:**
- Task 1 修改 AbstractCommand 添加配置选项，影响所有现有命令 → 缓解：新选项全部 optional，默认值保持现有行为
- Task 2 的 ResourcesCommand 需要关闭 skipResources 才能获取资源 → 缓解：仅在 resources 命令时动态覆盖 skipResources=false
- Task 4 的 UsageCommand 调用 getUseIn/getUsed 需要先触发反编译 → 缓解：在 execute 中先调用 cls.getCode() 触发

---

### Task 1: 增强 AbstractCommand 支持 JadxArgs 配置选项

**Depends on:** None
**Files:**
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/AbstractCommand.java:17-53`

- [ ] **Step 1: 修改 AbstractCommand 以支持反编译配置选项**

文件: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/AbstractCommand.java`

```java
package jadx.ai.cli.commands;

import java.io.File;
import java.io.PrintStream;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.CommentsLevel;
import jadx.api.DecompilationMode;
import jadx.api.JadxArgs;
import jadx.api.JadxDecompiler;
import jadx.api.impl.NoOpCodeCache;
import jadx.api.usage.impl.EmptyUsageInfoCache;

public abstract class AbstractCommand implements Runnable {

	@Parameters(index = "0", description = "Input file (APK, DEX, JAR, AAR, or class)")
	protected File inputFile;

	@Option(names = { "--format" }, description = "Output format: json (default) or plain", defaultValue = "json")
	protected String format;

	@Option(names = { "--decompilation-mode" }, description = "Decompilation mode: AUTO, RESTRUCTURE, SIMPLE, FALLBACK", defaultValue = "AUTO")
	protected String decompilationMode;

	@Option(names = { "--show-bad-code" }, description = "Show inconsistent code (bad code)")
	protected boolean showBadCode;

	@Option(names = { "--deobfuscation" }, description = "Enable deobfuscation")
	protected boolean deobfuscation;

	@Option(names = { "--comments-level" }, description = "Comments level: NONE, USER_ONLY, ERROR, WARN, INFO, DEBUG", defaultValue = "WARN")
	protected String commentsLevel;

	@Option(names = { "--include-resources" }, description = "Include resources (not skip them)")
	protected boolean includeResources;

	private static final Gson GSON = new GsonBuilder()
			.setPrettyPrinting()
			.disableHtmlEscaping()
			.create();

	@Override
	public void run() {
		JadxDecompiler decompiler = null;
		try {
			JadxArgs args = new JadxArgs();
			args.setInputFile(inputFile);
			args.setSkipResources(!includeResources);
			args.setShowInconsistentCode(showBadCode);
			args.setDeobfuscationOn(deobfuscation);
			args.setDecompilationMode(DecompilationMode.valueOf(decompilationMode.toUpperCase()));
			args.setCommentsLevel(CommentsLevel.valueOf(commentsLevel.toUpperCase()));
			args.setCodeCache(new NoOpCodeCache());
			args.setUsageInfoCache(new EmptyUsageInfoCache());

			decompiler = new JadxDecompiler(args);
			decompiler.load();

			Object result = execute(decompiler);
			outputResult(result, System.out);
		} catch (Exception e) {
			JsonOutput error = JsonOutput.error(e.getClass().getSimpleName(), e.getMessage());
			outputResult(error, System.err);
		} finally {
			if (decompiler != null) {
				decompiler.close();
			}
		}
	}

	protected abstract Object execute(JadxDecompiler decompiler) throws Exception;

	protected void outputResult(Object data, PrintStream out) {
		if ("json".equals(format)) {
			out.println(GSON.toJson(data));
		} else {
			out.println(data);
		}
	}
}
```

- [ ] **Step 2: 验证 AbstractCommand 修改后构建通过**
Run: `export JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home && export PATH="$JAVA_HOME/bin:$PATH" && ./gradlew :jadx-ai-cli:spotlessApply :jadx-ai-cli:compileJava --no-daemon 2>&1 | tail -5`
Expected:
  - Exit code: 0
  - Output contains: "BUILD SUCCESSFUL"

- [ ] **Step 3: 提交**
Run: `git add jadx-ai-cli/src/main/java/jadx/ai/cli/commands/AbstractCommand.java && git commit -m "feat(jadx-ai-cli): add decompilation config options to AbstractCommand"`

---

### Task 2: 创建 ResourcesCommand — 暴露资源文件访问能力

**Depends on:** Task 1
**Files:**
- Create: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/ResourcesCommand.java`
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/JadxAICLI.java:16-22`

- [ ] **Step 1: 创建 ResourcesCommand — 列出和读取 APK 内嵌资源文件**

```java
package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.List;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.ResourceFile;
import jadx.api.ResourceType;

@Command(name = "resources", description = "List and read embedded resource files (AndroidManifest, XML, ARSC, etc.)")
public class ResourcesCommand extends AbstractCommand {

	@Option(names = { "-t", "--type" }, description = "Filter by resource type: MANIFEST, XML, ARSC, IMG, FONT, JSON, TEXT, HTML, LIB, CODE, APK, ARCHIVE, VIDEOS, SOUNDS")
	protected String resourceType;

	@Option(names = { "-n", "--name" }, description = "Filter by resource name (substring match)")
	protected String nameFilter;

	@Option(names = { "--content" }, description = "Include resource content (text resources only)")
	protected boolean includeContent;

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		List<ResourceInfo> results = new ArrayList<>();
		for (ResourceFile res : decompiler.getResources()) {
			if (resourceType != null) {
				try {
					ResourceType filterType = ResourceType.valueOf(resourceType.toUpperCase());
					if (res.getType() != filterType) {
						continue;
					}
				} catch (IllegalArgumentException e) {
					return JsonOutput.error("InvalidResourceType",
							"Unknown resource type: " + resourceType);
				}
			}
			if (nameFilter != null && !res.getOriginalName().contains(nameFilter)) {
				continue;
			}
			ResourceInfo info = new ResourceInfo();
			info.name = res.getOriginalName();
			info.type = res.getType().name();
			if (includeContent && res.getType().getContentType() == jadx.api.resources.ResourceContentType.CONTENT_TEXT) {
				try {
					var container = res.loadContent();
					if (container != null) {
						info.content = container.getText().toString();
					}
				} catch (Exception e) {
					info.content = null;
				}
			}
			results.add(info);
		}
		return JsonOutput.list(results);
	}

	static class ResourceInfo {
		String name;
		String type;
		String content;
	}
}
```

- [ ] **Step 2: 注册 ResourcesCommand 到 JadxAICLI**

文件: `jadx-ai-cli/src/main/java/jadx/ai/cli/JadxAICLI.java`

在 subcommands 数组中添加 `ResourcesCommand.class`，并在 import 区添加 `import jadx.ai.cli.commands.ResourcesCommand;`

- [ ] **Step 3: 验证 ResourcesCommand 构建通过**
Run: `export JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home && export PATH="$JAVA_HOME/bin:$PATH" && ./gradlew :jadx-ai-cli:spotlessApply :jadx-ai-cli:compileJava --no-daemon 2>&1 | tail -5`
Expected:
  - Exit code: 0
  - Output contains: "BUILD SUCCESSFUL"

- [ ] **Step 4: 提交**
Run: `git add jadx-ai-cli/src/main/java/jadx/ai/cli/commands/ResourcesCommand.java jadx-ai-cli/src/main/java/jadx/ai/cli/JadxAICLI.java && git commit -m "feat(jadx-ai-cli): add resources command for embedded resource file access"`

---

### Task 3: 创建 UsageCommand — 暴露使用关系/调用图能力

**Depends on:** Task 1
**Files:**
- Create: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/UsageCommand.java`
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/JadxAICLI.java`

- [ ] **Step 1: 创建 UsageCommand — 查询类/方法/字段的使用关系**

```java
package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.api.JavaField;
import jadx.api.JavaMethod;
import jadx.api.JavaNode;

@Command(name = "usage", description = "Query usage relationships (call graph, references)")
public class UsageCommand extends AbstractCommand {

	@Option(names = { "-c", "--class" }, description = "Class name to query usage for")
	protected String className;

	@Option(names = { "-m", "--method" }, description = "Method name to query usage for (requires --class)")
	protected String methodName;

	@Option(names = { "-f", "--field" }, description = "Field name to query usage for (requires --class)")
	protected String fieldName;

	@Option(names = { "-t", "--type" }, description = "Query type: useIn (who uses this) or used (what this uses)", defaultValue = "useIn")
	protected String queryType;

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		if (className == null) {
			return JsonOutput.error("MissingClass", "--class is required");
		}
		JavaClass cls = decompiler.searchJavaClassByOrigFullName(className);
		if (cls == null) {
			List<JavaClass> matches = decompiler.getClasses()
					.stream()
					.filter(c -> c.getFullName().contains(className))
					.collect(Collectors.toList());
			if (matches.isEmpty()) {
				return JsonOutput.error("ClassNotFound", "Class not found: " + className);
			}
			cls = matches.get(0);
		}

		if (methodName != null) {
			return queryMethodUsage(cls, methodName);
		}
		if (fieldName != null) {
			return queryFieldUsage(cls, fieldName);
		}
		return queryClassUsage(cls);
	}

	private Object queryClassUsage(JavaClass cls) {
		cls.getCode();
		List<UsageRef> refs = new ArrayList<>();
		for (JavaNode node : cls.getUseIn()) {
			UsageRef ref = new UsageRef();
			ref.name = node.getFullName();
			ref.nodeType = getNodeType(node);
			refs.add(ref);
		}
		UsageResult result = new UsageResult();
		result.target = cls.getFullName();
		result.targetType = "class";
		result.references = refs;
		return JsonOutput.ok(result);
	}

	private Object queryMethodUsage(JavaClass cls, String methodName) {
		cls.getCode();
		List<JavaMethod> methods = cls.getMethods()
				.stream()
				.filter(m -> m.getName().equals(methodName))
				.collect(Collectors.toList());
		if (methods.isEmpty()) {
			return JsonOutput.error("MethodNotFound", "Method not found: " + methodName);
		}
		JavaMethod mth = methods.get(0);
		List<UsageRef> refs = new ArrayList<>();
		List<JavaNode> nodes = "used".equals(queryType) ? mth.getUsed() : mth.getUseIn();
		for (JavaNode node : nodes) {
			UsageRef ref = new UsageRef();
			ref.name = node.getFullName();
			ref.nodeType = getNodeType(node);
			refs.add(ref);
		}
		UsageResult result = new UsageResult();
		result.target = mth.getFullName();
		result.targetType = "method";
		result.queryType = queryType;
		result.references = refs;
		return JsonOutput.ok(result);
	}

	private Object queryFieldUsage(JavaClass cls, String fieldName) {
		cls.getCode();
		JavaField target = null;
		for (JavaField f : cls.getFields()) {
			if (f.getName().equals(fieldName)) {
				target = f;
				break;
			}
		}
		if (target == null) {
			return JsonOutput.error("FieldNotFound", "Field not found: " + fieldName);
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
		result.references = refs;
		return JsonOutput.ok(result);
	}

	private String getNodeType(JavaNode node) {
		if (node instanceof JavaClass) {
			return "class";
		}
		if (node instanceof JavaMethod) {
			return "method";
		}
		if (node instanceof JavaField) {
			return "field";
		}
		return "unknown";
	}

	static class UsageResult {
		String target;
		String targetType;
		String queryType;
		List<UsageRef> references;
	}

	static class UsageRef {
		String name;
		String nodeType;
	}
}
```

- [ ] **Step 2: 注册 UsageCommand 到 JadxAICLI**

在 JadxAICLI.java 的 subcommands 数组中添加 `UsageCommand.class`，添加 import

- [ ] **Step 3: 验证 UsageCommand 构建通过**
Run: `export JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home && export PATH="$JAVA_HOME/bin:$PATH" && ./gradlew :jadx-ai-cli:spotlessApply :jadx-ai-cli:compileJava --no-daemon 2>&1 | tail -5`
Expected:
  - Exit code: 0
  - Output contains: "BUILD SUCCESSFUL"

- [ ] **Step 4: 提交**
Run: `git add jadx-ai-cli/src/main/java/jadx/ai/cli/commands/UsageCommand.java jadx-ai-cli/src/main/java/jadx/ai/cli/JadxAICLI.java && git commit -m "feat(jadx-ai-cli): add usage command for call graph and reference queries"`

---

### Task 4: 创建 ClassDetailCommand — 暴露类继承/内部类/访问修饰符能力

**Depends on:** Task 1
**Files:**
- Create: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/ClassDetailCommand.java`
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/JadxAICLI.java`

- [ ] **Step 1: 创建 ClassDetailCommand — 查询类的完整结构信息**

```java
package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.api.JavaField;
import jadx.api.JavaMethod;

@Command(name = "class-detail", description = "Get detailed class structure (inheritance, inner classes, access flags, method signatures)")
public class ClassDetailCommand extends AbstractCommand {

	@Option(names = { "-c", "--class" }, description = "Full class name", required = true)
	protected String className;

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		JavaClass cls = decompiler.searchJavaClassByOrigFullName(className);
		if (cls == null) {
			List<JavaClass> matches = decompiler.getClasses()
					.stream()
					.filter(c -> c.getFullName().contains(className))
					.collect(Collectors.toList());
			if (matches.isEmpty()) {
				return JsonOutput.error("ClassNotFound", "Class not found: " + className);
			}
			if (matches.size() > 1) {
				List<String> names = matches.stream()
						.map(JavaClass::getFullName)
						.collect(Collectors.toList());
				return JsonOutput.error("AmbiguousClass",
						"Multiple classes match. Specify full name: " + names);
			}
			cls = matches.get(0);
		}

		ClassDetail detail = new ClassDetail();
		detail.fullName = cls.getFullName();
		detail.simpleName = cls.getName();
		detail.packageName = cls.getPackage();
		detail.rawName = cls.getRawName();
		detail.isInner = cls.isInner();
		detail.accessFlags = cls.getAccessInfo().rawValue();
		detail.accessStr = cls.getAccessInfo().toString();

		if (cls.getDeclaringClass() != null) {
			detail.declaringClass = cls.getDeclaringClass().getFullName();
		}
		detail.topParentClass = cls.getTopParentClass().getFullName();

		detail.innerClasses = new ArrayList<>();
		for (JavaClass inner : cls.getInnerClasses()) {
			detail.innerClasses.add(inner.getFullName());
		}

		detail.inlinedClasses = new ArrayList<>();
		for (JavaClass inlined : cls.getInlinedClasses()) {
			detail.inlinedClasses.add(inlined.getFullName());
		}

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
			md.accessFlags = m.getAccessFlags().rawValue();
			md.accessStr = m.getAccessFlags().toString();
			detail.methods.add(md);
		}

		detail.fields = new ArrayList<>();
		for (JavaField f : cls.getFields()) {
			FieldDetail fd = new FieldDetail();
			fd.name = f.getName();
			fd.type = f.getType().toString();
			fd.accessFlags = f.getAccessFlags().rawValue();
			fd.accessStr = f.getAccessFlags().toString();
			detail.fields.add(fd);
		}

		return JsonOutput.ok(detail);
	}

	static class ClassDetail {
		String fullName;
		String simpleName;
		String packageName;
		String rawName;
		boolean isInner;
		int accessFlags;
		String accessStr;
		String declaringClass;
		String topParentClass;
		List<String> innerClasses;
		List<String> inlinedClasses;
		List<MethodDetail> methods;
		List<FieldDetail> fields;
	}

	static class MethodDetail {
		String name;
		String returnType;
		List<String> arguments;
		boolean isConstructor;
		int accessFlags;
		String accessStr;
	}

	static class FieldDetail {
		String name;
		String type;
		int accessFlags;
		String accessStr;
	}
}
```

- [ ] **Step 2: 注册 ClassDetailCommand 到 JadxAICLI**

在 JadxAICLI.java 的 subcommands 数组中添加 `ClassDetailCommand.class`，添加 import

- [ ] **Step 3: 验证 ClassDetailCommand 构建通过**
Run: `export JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home && export PATH="$JAVA_HOME/bin:$PATH" && ./gradlew :jadx-ai-cli:spotlessApply :jadx-ai-cli:compileJava --no-daemon 2>&1 | tail -5`
Expected:
  - Exit code: 0
  - Output contains: "BUILD SUCCESSFUL"

- [ ] **Step 4: 提交**
Run: `git add jadx-ai-cli/src/main/java/jadx/ai/cli/commands/ClassDetailCommand.java jadx-ai-cli/src/main/java/jadx/ai/cli/JadxAICLI.java && git commit -m "feat(jadx-ai-cli): add class-detail command for inheritance and structure info"`

---

### Task 5: 增强现有命令 + InfoCommand 添加 errors/warns/version

**Depends on:** Task 1
**Files:**
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/InfoCommand.java:11-28`
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/ListCommand.java`
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/SearchCommand.java`

- [ ] **Step 1: 增强 InfoCommand 添加 errorsCount/warnsCount/version/totalResources**

文件: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/InfoCommand.java`

```java
package jadx.ai.cli.commands;

import picocli.CommandLine.Command;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;

@Command(name = "info", description = "Show APK/DEX file metadata and statistics")
public class InfoCommand extends AbstractCommand {

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		ApkInfo info = new ApkInfo();
		info.fileName = inputFile.getName();
		info.filePath = inputFile.getAbsolutePath();
		info.fileSize = inputFile.length();
		info.totalClasses = decompiler.getClasses().size();
		info.totalPackages = decompiler.getPackages().size();
		info.totalResources = decompiler.getResources().size();
		info.errorsCount = decompiler.getErrorsCount();
		info.warnsCount = decompiler.getWarnsCount();
		info.version = jadx.api.JadxDecompiler.getVersion();

		int methodCount = 0;
		int fieldCount = 0;
		for (jadx.api.JavaClass cls : decompiler.getClasses()) {
			methodCount += cls.getMethods().size();
			fieldCount += cls.getFields().size();
		}
		info.totalMethods = methodCount;
		info.totalFields = fieldCount;

		return JsonOutput.ok(info);
	}

	static class ApkInfo {
		String fileName;
		String filePath;
		long fileSize;
		int totalClasses;
		int totalPackages;
		int totalMethods;
		int totalFields;
		int totalResources;
		int errorsCount;
		int warnsCount;
		String version;
	}
}
```

- [ ] **Step 2: 增强 ListCommand 的 listClasses 添加 isInner 和 accessFlags**

文件: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/ListCommand.java`

在 ClassInfo 中添加 `boolean isInner` 和 `String accessStr` 字段，在 listClasses 方法中赋值 `info.isInner = cls.isInner()` 和 `info.accessStr = cls.getAccessInfo().toString()`

- [ ] **Step 3: 增强 SearchCommand 的方法搜索添加 returnType 和 arguments**

文件: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/SearchCommand.java`

在 MethodSearchResult 中添加 `String returnType` 字段，在 searchMethods 方法中赋值 `r.returnType = m.getReturnType().toString()`。在 FieldSearchResult 中添加 `String type` 字段，在 searchFields 方法中赋值 `r.type = f.getType().toString()`

- [ ] **Step 4: 验证增强后构建通过**
Run: `export JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home && export PATH="$JAVA_HOME/bin:$PATH" && ./gradlew :jadx-ai-cli:spotlessApply :jadx-ai-cli:compileJava --no-daemon 2>&1 | tail -5`
Expected:
  - Exit code: 0
  - Output contains: "BUILD SUCCESSFUL"

- [ ] **Step 5: 提交**
Run: `git add jadx-ai-cli/src/main/java/jadx/ai/cli/commands/InfoCommand.java jadx-ai-cli/src/main/java/jadx/ai/cli/commands/ListCommand.java jadx-ai-cli/src/main/java/jadx/ai/cli/commands/SearchCommand.java && git commit -m "feat(jadx-ai-cli): enhance info/list/search with errors, resources, access flags, method signatures"`

---

### Task 6: 完整构建验证 + 测试 + Skills 更新

**Depends on:** Task 2, Task 3, Task 4, Task 5
**Files:**
- Modify: `jadx-ai-cli/src/test/java/jadx/ai/cli/CommandsTest.java`
- Create: `.claude/skills/jadx-resources.md`
- Create: `.claude/skills/jadx-usage.md`
- Create: `.claude/skills/jadx-class-detail.md`
- Modify: `.claude/skills/jadx-info.md`
- Modify: `.claude/skills/jadx-analyze.md`

- [ ] **Step 1: 更新 CommandsTest 添加新命令测试**

文件: `jadx-ai-cli/src/test/java/jadx/ai/cli/CommandsTest.java`

在现有测试类中添加 3 个新测试方法：testResourcesCommand、testUsageCommand、testClassDetailCommand，使用与现有测试相同的 runCommand 模式

- [ ] **Step 2: 运行完整构建（含 checkstyle + spotless + test）**
Run: `export JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home && export PATH="$JAVA_HOME/bin:$PATH" && ./gradlew :jadx-ai-cli:spotlessApply :jadx-ai-cli:build --no-daemon 2>&1 | tail -10`
Expected:
  - Exit code: 0
  - Output contains: "BUILD SUCCESSFUL"

- [ ] **Step 3: 验证 CLI help 输出包含所有 9 个子命令**
Run: `export JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home && export PATH="$JAVA_HOME/bin:$PATH" && ./gradlew :jadx-ai-cli:run --args="--help" --no-daemon 2>&1 | grep "Commands:" -A 10`
Expected:
  - Output contains: "decompile", "search", "list", "export", "info", "script", "resources", "usage", "class-detail"

- [ ] **Step 4: 创建 jadx-resources skill**

```markdown
---
name: jadx-resources
description: List and read embedded resource files from Android APK using JADX AI-CLI. Access AndroidManifest.xml, layouts, strings, images, etc.
---

# JADX Resources Skill

List and read embedded resource files from an Android APK.

## Usage

When the user asks about Android resources, manifests, layouts, or embedded files:

1. Run the JADX AI-CLI resources command
2. Present the structured results

## Command

```bash
jadx-ai resources [--include-resources] [-t <type>] [-n <name>] [--content] <input-file>
```

## Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `<input-file>` | Yes | Path to APK file |
| `--include-resources` | Yes | Must include this flag to load resources |
| `-t, --type` | No | Filter by type: MANIFEST, XML, ARSC, IMG, FONT, JSON, TEXT, HTML, LIB |
| `-n, --name` | No | Filter by name (substring match) |
| `--content` | No | Include text content of resources |

## Examples

```bash
# List all resources
jadx-ai resources --include-resources app.apk

# Get AndroidManifest
jadx-ai resources --include-resources -t MANIFEST app.apk

# Search for layout XMLs
jadx-ai resources --include-resources -t XML -n "layout" app.apk

# Read string resources with content
jadx-ai resources --include-resources -t ARSC --content app.apk
```
```

- [ ] **Step 5: 创建 jadx-usage skill**

```markdown
---
name: jadx-usage
description: Query usage relationships and call graph from Android APK using JADX AI-CLI. Find who calls a method, who references a class, etc.
---

# JADX Usage Skill

Query usage relationships (call graph, references) from decompiled Android code.

## Usage

When the user asks about call graphs, references, who uses what, or code relationships:

1. Run the JADX AI-CLI usage command
2. Present the structured results

## Command

```bash
jadx-ai usage -c <class> [-m <method>] [-f <field>] [-t <type>] <input-file>
```

## Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `<input-file>` | Yes | Path to APK, DEX file |
| `-c, --class` | Yes | Class name to query |
| `-m, --method` | No | Method name (requires --class) |
| `-f, --field` | No | Field name (requires --class) |
| `-t, --type` | No | Query type: useIn (who uses this) or used (what this uses) |

## Examples

```bash
# Who uses this class?
jadx-ai usage -c com.example.MyClass app.apk

# Who calls this method?
jadx-ai usage -c com.example.MyClass -m doSomething app.apk

# What methods does this method call?
jadx-ai usage -c com.example.MyClass -m doSomething -t used app.apk

# Who references this field?
jadx-ai usage -c com.example.MyClass -f myField app.apk
```
```

- [ ] **Step 6: 创建 jadx-class-detail skill**

```markdown
---
name: jadx-class-detail
description: Get detailed class structure from Android APK using JADX AI-CLI. Includes inheritance, inner classes, access flags, full method signatures.
---

# JADX Class Detail Skill

Get detailed class structure information including inheritance, inner classes, access flags, and full method signatures.

## Usage

When the user asks about class structure, inheritance hierarchy, method signatures, or access modifiers:

1. Run the JADX AI-CLI class-detail command
2. Present the structured results

## Command

```bash
jadx-ai class-detail -c <class-name> <input-file>
```

## Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `<input-file>` | Yes | Path to APK, DEX file |
| `-c, --class` | Yes | Full class name |

## Examples

```bash
# Get full class details
jadx-ai class-detail -c com.example.MyClass app.apk

# Get details for an Activity
jadx-ai class-detail -c com.example.app.MainActivity app.apk
```
```

- [ ] **Step 7: 更新 jadx-info skill 添加新字段**

在 `.claude/skills/jadx-info.md` 的 Output Format JSON 示例中添加 `totalResources`, `errorsCount`, `warnsCount`, `version` 字段

- [ ] **Step 8: 更新 jadx-analyze skill 添加新命令到工作流**

在 `.claude/skills/jadx-analyze.md` 的 Workflow Commands 和 Common Analysis Patterns 中添加 resources、usage、class-detail 命令示例

- [ ] **Step 9: 提交所有 Skills 和测试**
Run: `git add jadx-ai-cli/src/test/java/jadx/ai/cli/CommandsTest.java .claude/skills/ && git commit -m "feat(jadx-ai-cli): add tests and skills for resources, usage, class-detail commands"`
