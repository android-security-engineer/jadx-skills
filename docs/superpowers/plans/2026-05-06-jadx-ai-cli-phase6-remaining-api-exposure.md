# jadx-ai-cli Phase 6: 补全剩余 JADX API 能力暴露

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** 将 JADX 反编译器所有尚未暴露到 jadx-ai-cli 的公开 API 方法集成到 CLI 入口中，包括重命名/别名操作、重新反编译/卸载、分离保存源码/资源、包级引用查询、安全标志配置等。

**Architecture:** 用户通过 CLI 命令 → picocli 解析参数 → AbstractCommand 创建 JadxDecompiler → 具体 Command.execute() 调用 JADX API → JsonOutput 封装结果。新增 RenameCommand 和 ReloadCommand 两个命令，增强 ExportCommand、UsageCommand、ClassDetailCommand 和 AbstractCommand。

**Tech Stack:** Java 21, picocli 4.7.5, Gson 2.10.1, JADX core API, JUnit 5

**Risks:**
- Task 1 的 rename/removeAlias 操作会修改反编译器内部状态 → 缓解：在命令输出中明确提示状态已修改
- Task 2 的 reload/unload 操作会触发重新反编译，可能耗时较长 → 缓解：在命令描述中说明此行为
- Task 4 新增 --security-flags 选项需要解析 EnumSet → 缓解：使用逗号分隔的枚举值字符串

---

### Task 1: 创建 RenameCommand — 暴露重命名和别名操作

**Depends on:** None
**Files:**
- Create: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/RenameCommand.java`
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/JadxAiCli.java:16`（注册新命令）

- [ ] **Step 1: 创建 RenameCommand — 支持对类/方法/字段/包/资源进行重命名和移除别名**

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
import jadx.api.JavaPackage;

@Command(name = "rename", description = "Rename classes, methods, fields, packages, or remove aliases")
public class RenameCommand extends AbstractCommand {

	@Option(names = { "-t", "--type" }, description = "Target type: class, method, field, package", required = true)
	protected String targetType;

	@Option(names = { "-c", "--class" }, description = "Class full name")
	protected String className;

	@Option(names = { "-m", "--method" }, description = "Method name (requires --class)")
	protected String methodName;

	@Option(names = { "-f", "--field" }, description = "Field name (requires --class)")
	protected String fieldName;

	@Option(names = { "-p", "--package" }, description = "Package full name")
	protected String packageName;

	@Option(names = { "-n", "--name" }, description = "New name (alias) to set")
	protected String newName;

	@Option(names = { "--remove-alias" }, description = "Remove alias and revert to original name")
	protected boolean removeAlias;

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		if (newName == null && !removeAlias) {
			return JsonOutput.error("MissingAction",
					"Specify --name <newName> to rename or --remove-alias to revert");
		}
		switch (targetType.toLowerCase()) {
			case "class":
				return renameClass(decompiler);
			case "method":
				return renameMethod(decompiler);
			case "field":
				return renameField(decompiler);
			case "package":
				return renamePackage(decompiler);
			default:
				return JsonOutput.error("InvalidTargetType",
						"Unknown type: " + targetType + ". Use: class, method, field, package");
		}
	}

	private JavaClass resolveClass(JadxDecompiler decompiler, String name) {
		if (name == null) {
			return null;
		}
		JavaClass cls = decompiler.searchJavaClassByOrigFullName(name);
		if (cls == null) {
			List<JavaClass> matches = decompiler.getClasses()
					.stream()
					.filter(c -> c.getFullName().contains(name))
					.collect(Collectors.toList());
			if (matches.size() == 1) {
				return matches.get(0);
			}
		}
		return cls;
	}

	private Object renameClass(JadxDecompiler decompiler) {
		if (className == null) {
			return JsonOutput.error("MissingClass", "--class is required");
		}
		JavaClass cls = resolveClass(decompiler, className);
		if (cls == null) {
			return JsonOutput.error("ClassNotFound", "Class not found: " + className);
		}
		String oldName = cls.getFullName();
		if (removeAlias) {
			cls.removeAlias();
		}
		RenameResult result = new RenameResult();
		result.targetType = "class";
		result.oldName = oldName;
		result.newName = removeAlias ? cls.getFullName() : newName;
		result.action = removeAlias ? "removeAlias" : "rename";
		return JsonOutput.ok(result);
	}

	private Object renameMethod(JadxDecompiler decompiler) {
		if (className == null || methodName == null) {
			return JsonOutput.error("MissingParams", "--class and --method are required");
		}
		JavaClass cls = resolveClass(decompiler, className);
		if (cls == null) {
			return JsonOutput.error("ClassNotFound", "Class not found: " + className);
		}
		List<JavaMethod> methods = cls.getMethods()
				.stream()
				.filter(m -> m.getName().equals(methodName))
				.collect(Collectors.toList());
		if (methods.isEmpty()) {
			return JsonOutput.error("MethodNotFound", "Method not found: " + methodName);
		}
		List<RenameResult> results = new ArrayList<>();
		for (JavaMethod m : methods) {
			String oldName = m.getFullName();
			if (removeAlias) {
				m.removeAlias();
			}
			RenameResult r = new RenameResult();
			r.targetType = "method";
			r.oldName = oldName;
			r.newName = removeAlias ? m.getFullName() : newName;
			r.action = removeAlias ? "removeAlias" : "rename";
			results.add(r);
		}
		return JsonOutput.list(results);
	}

	private Object renameField(JadxDecompiler decompiler) {
		if (className == null || fieldName == null) {
			return JsonOutput.error("MissingParams", "--class and --field are required");
		}
		JavaClass cls = resolveClass(decompiler, className);
		if (cls == null) {
			return JsonOutput.error("ClassNotFound", "Class not found: " + className);
		}
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
		String oldName = target.getFullName();
		if (removeAlias) {
			target.removeAlias();
		}
		RenameResult result = new RenameResult();
		result.targetType = "field";
		result.oldName = oldName;
		result.newName = removeAlias ? target.getFullName() : newName;
		result.action = removeAlias ? "removeAlias" : "rename";
		return JsonOutput.ok(result);
	}

	private Object renamePackage(JadxDecompiler decompiler) {
		if (packageName == null) {
			return JsonOutput.error("MissingPackage", "--package is required");
		}
		JavaPackage targetPkg = null;
		for (JavaPackage pkg : decompiler.getPackages()) {
			if (pkg.getFullName().equals(packageName)) {
				targetPkg = pkg;
				break;
			}
		}
		if (targetPkg == null) {
			return JsonOutput.error("PackageNotFound", "Package not found: " + packageName);
		}
		String oldName = targetPkg.getFullName();
		if (removeAlias) {
			targetPkg.removeAlias();
		} else {
			targetPkg.rename(newName);
		}
		RenameResult result = new RenameResult();
		result.targetType = "package";
		result.oldName = oldName;
		result.newName = removeAlias ? targetPkg.getFullName() : newName;
		result.action = removeAlias ? "removeAlias" : "rename";
		return JsonOutput.ok(result);
	}

	static class RenameResult {
		String targetType;
		String oldName;
		String newName;
		String action;
	}
}
```

- [ ] **Step 2: 注册 RenameCommand 到 JadxAiCli — 将新命令添加到 CLI 入口**
文件: `jadx-ai-cli/src/main/java/jadx/ai/cli/JadxAiCli.java:16`

```java
// 替换 JadxAiCli.java 第 16 行的 @Command 注解 subcommands 列表
// 在现有 subcommands 列表末尾添加 RenameCommand.class 和 ReloadCommand.class
```

- [ ] **Step 3: 验证 RenameCommand 编译**
Run: `JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :jadx-ai-cli:spotlessApply :jadx-ai-cli:compileJava 2>&1 | tail -5`
Expected:
  - Exit code: 0
  - Output contains: "BUILD SUCCESSFUL"

- [ ] **Step 4: 提交**
Run: `git add jadx-ai-cli/src/main/java/jadx/ai/cli/commands/RenameCommand.java jadx-ai-cli/src/main/java/jadx/ai/cli/JadxAiCli.java && git commit -m "feat(jadx-ai-cli): add rename command for class/method/field/package rename and alias removal"`

---

### Task 2: 创建 ReloadCommand — 暴露重新反编译和卸载操作

**Depends on:** Task 1
**Files:**
- Create: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/ReloadCommand.java`

- [ ] **Step 1: 创建 ReloadCommand — 支持重新反编译类、卸载类代码、重新加载代码数据**

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

@Command(name = "reload", description = "Reload, recompile, or unload class code")
public class ReloadCommand extends AbstractCommand {

	@Option(names = { "-c", "--class" }, description = "Class full name to reload/unload")
	protected String className;

	@Option(names = { "-t", "--type" }, description = "Action: reload (recompile class), unload (free code), codeData (refresh all code data)", defaultValue = "reload")
	protected String actionType;

	@Option(names = { "--all" }, description = "Apply action to all classes (use with caution)")
	protected boolean allClasses;

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		switch (actionType.toLowerCase()) {
			case "reload":
				return reloadClass(decompiler);
			case "unload":
				return unloadClass(decompiler);
			case "codedata":
				decompiler.reloadCodeData();
				ReloadResult result = new ReloadResult();
				result.action = "codeData";
				result.message = "Code data reloaded for all classes";
				return JsonOutput.ok(result);
			default:
				return JsonOutput.error("InvalidAction",
						"Unknown action: " + actionType + ". Use: reload, unload, codeData");
		}
	}

	private Object reloadClass(JadxDecompiler decompiler) {
		if (allClasses) {
			List<ReloadResult> results = new ArrayList<>();
			for (JavaClass cls : decompiler.getClasses()) {
				ReloadResult r = new ReloadResult();
				r.className = cls.getFullName();
				r.action = "reload";
				try {
					cls.reload();
					r.success = true;
				} catch (Exception e) {
					r.success = false;
					r.message = e.getMessage();
				}
				results.add(r);
			}
			return JsonOutput.list(results);
		}
		if (className == null) {
			return JsonOutput.error("MissingClass", "--class or --all is required");
		}
		JavaClass cls = resolveClass(decompiler, className);
		if (cls == null) {
			return JsonOutput.error("ClassNotFound", "Class not found: " + className);
		}
		ReloadResult result = new ReloadResult();
		result.className = cls.getFullName();
		result.action = "reload";
		cls.reload();
		result.success = true;
		return JsonOutput.ok(result);
	}

	private Object unloadClass(JadxDecompiler decompiler) {
		if (allClasses) {
			List<ReloadResult> results = new ArrayList<>();
			for (JavaClass cls : decompiler.getClasses()) {
				ReloadResult r = new ReloadResult();
				r.className = cls.getFullName();
				r.action = "unload";
				cls.unload();
				r.success = true;
				results.add(r);
			}
			return JsonOutput.list(results);
		}
		if (className == null) {
			return JsonOutput.error("MissingClass", "--class or --all is required");
		}
		JavaClass cls = resolveClass(decompiler, className);
		if (cls == null) {
			return JsonOutput.error("ClassNotFound", "Class not found: " + className);
		}
		ReloadResult result = new ReloadResult();
		result.className = cls.getFullName();
		result.action = "unload";
		cls.unload();
		result.success = true;
		return JsonOutput.ok(result);
	}

	private JavaClass resolveClass(JadxDecompiler decompiler, String name) {
		JavaClass cls = decompiler.searchJavaClassByOrigFullName(name);
		if (cls == null) {
			List<JavaClass> matches = decompiler.getClasses()
					.stream()
					.filter(c -> c.getFullName().contains(name))
					.collect(Collectors.toList());
			if (matches.size() == 1) {
				return matches.get(0);
			}
		}
		return cls;
	}

	static class ReloadResult {
		String className;
		String action;
		boolean success;
		String message;
	}
}
```

- [ ] **Step 2: 验证 ReloadCommand 编译**
Run: `JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :jadx-ai-cli:spotlessApply :jadx-ai-cli:compileJava 2>&1 | tail -5`
Expected:
  - Exit code: 0
  - Output contains: "BUILD SUCCESSFUL"

- [ ] **Step 3: 提交**
Run: `git add jadx-ai-cli/src/main/java/jadx/ai/cli/commands/ReloadCommand.java && git commit -m "feat(jadx-ai-cli): add reload command for class recompile, unload, and code data refresh"`

---

### Task 3: 增强 ExportCommand — 暴露 saveSources/saveResources 分离保存

**Depends on:** Task 2
**Files:**
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/ExportCommand.java:20-33`

- [ ] **Step 1: 修改 ExportCommand 以支持 --save-sources 和 --save-resources 选项**
文件: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/ExportCommand.java:20-33`（选项声明区域）

在现有 `--save-all` 选项之后添加两个新选项：

```java
@Option(names = { "--save-sources" }, description = "Use JADX saveSources() to export only sources to output dir")
protected boolean saveSources;

@Option(names = { "--save-resources" }, description = "Use JADX saveResources() to export only resources to output dir")
protected boolean saveResources;
```

- [ ] **Step 2: 修改 ExportCommand.execute() 以处理新保存模式**
文件: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/ExportCommand.java:36-52`（saveAll 处理区域之后）

在 `if (saveAll)` 块之后添加：

```java
if (saveSources) {
	decompiler.getArgs().setOutDir(outputDir);
	decompiler.getArgs().setOutDirSrc(new File(outputDir, "sources"));
	decompiler.saveSources();
	ExportSummary summary = new ExportSummary();
	summary.exportedCount = decompiler.getClasses().size();
	summary.errorCount = 0;
	summary.outputDir = outputDir.getAbsolutePath();
	return JsonOutput.ok(summary);
}

if (saveResources) {
	decompiler.getArgs().setOutDir(outputDir);
	decompiler.getArgs().setOutDirRes(new File(outputDir, "resources"));
	decompiler.saveResources();
	ExportSummary summary = new ExportSummary();
	summary.exportedCount = decompiler.getResources().size();
	summary.errorCount = 0;
	summary.outputDir = outputDir.getAbsolutePath();
	return JsonOutput.ok(summary);
}
```

- [ ] **Step 3: 验证 ExportCommand 编译**
Run: `JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :jadx-ai-cli:spotlessApply :jadx-ai-cli:compileJava 2>&1 | tail -5`
Expected:
  - Exit code: 0
  - Output contains: "BUILD SUCCESSFUL"

- [ ] **Step 4: 提交**
Run: `git add jadx-ai-cli/src/main/java/jadx/ai/cli/commands/ExportCommand.java && git commit -m "feat(jadx-ai-cli): add --save-sources and --save-resources options to export command"`

---

### Task 4: 增强 AbstractCommand 和 ClassDetailCommand — 暴露安全标志和类级补充 API

**Depends on:** Task 3
**Files:**
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/AbstractCommand.java:92-94`（添加安全标志选项）
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/ClassDetailCommand.java:109`（添加 javaPackage 和 searchMethodByShortId 字段）

- [ ] **Step 1: 添加 --security-flags 选项到 AbstractCommand — 控制安全检查行为**
文件: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/AbstractCommand.java`（在 `--plugin-options` 选项之后添加）

```java
@Option(names = { "--security-flags" }, description = "Security flags: VERIFY_APP_PACKAGE, SECURE_XML_PARSER, SECURE_ZIP_READER (comma-separated, default: all)", defaultValue = "")
protected String securityFlagsStr;
```

- [ ] **Step 2: 在 AbstractCommand.run() 中接线安全标志配置**
文件: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/AbstractCommand.java`（在 `args.setUseDxInput(useDxInput)` 之前添加）

```java
if (!securityFlagsStr.isEmpty()) {
	java.util.Set<jadx.api.security.JadxSecurityFlag> flags = new java.util.HashSet<>();
	for (String flag : securityFlagsStr.split(",")) {
		flags.add(jadx.api.security.JadxSecurityFlag.valueOf(flag.trim().toUpperCase()));
	}
	args.setSecurity(new jadx.api.security.impl.JadxSecurity(flags));
}
```

- [ ] **Step 3: 增强 ClassDetailCommand — 添加 javaPackage 和 methodShortId 字段**
文件: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/ClassDetailCommand.java:109`（在 ClassDetail 类中添加字段）

在 `detail.isNoCode = cls.isNoCode();` 之后添加：

```java
detail.javaPackage = cls.getJavaPackage().getFullName();
```

在 ClassDetail 类中添加字段：

```java
String javaPackage;
```

- [ ] **Step 4: 增强 ClassDetailCommand — 添加 --method-short-id 选项**
文件: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/ClassDetailCommand.java:19`（选项声明区域）

```java
@Option(names = { "--method-short-id" }, description = "Search method by short ID (e.g. 'onCreate(Landroid/os/Bundle;)V')")
protected String methodShortId;
```

在 execute() 方法的 `return JsonOutput.ok(detail);` 之前添加：

```java
if (methodShortId != null) {
	jadx.api.JavaMethod mth = cls.searchMethodByShortId(methodShortId);
	if (mth != null) {
		detail.foundMethod = mth.getFullName();
	}
}
```

在 ClassDetail 类中添加字段：

```java
String foundMethod;
```

- [ ] **Step 5: 验证全部编译和测试**
Run: `JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :jadx-ai-cli:spotlessApply :jadx-ai-cli:build 2>&1 | tail -10`
Expected:
  - Exit code: 0
  - Output contains: "BUILD SUCCESSFUL"

- [ ] **Step 6: 提交**
Run: `git add jadx-ai-cli/src/main/java/jadx/ai/cli/commands/AbstractCommand.java jadx-ai-cli/src/main/java/jadx/ai/cli/commands/ClassDetailCommand.java && git commit -m "feat(jadx-ai-cli): add security flags option and enhance class-detail with javaPackage and methodShortId"`
