# jadx-ai-cli Full Capability Exposure — Phase 2

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** 补充所有未暴露的 JADX API 能力到 jadx-ai-cli，确保逆向分析所需的全部功能可通过 CLI 命令获取。

**Architecture:** 现有 9 命令增强 + 2 新命令创建。AbstractCommand 增加 15 个配置选项 → 新命令 package-detail 和 line-map → 现有命令 class-detail/usage/search/list/decompile/resources/export 增强 → Skills 文件同步更新 → 测试 + 构建。

**Tech Stack:** Java 21, picocli 4.7.5, Gson 2.10.1, Gradle 9.4.1, JUnit 5

**Risks:**
- AbstractCommand 添加大量选项可能使 CLI help 输出过长 → 缓解：只添加对 AI 逆向分析有明确价值的选项，跳过内部/高级选项
- line-map 命令依赖 ICodeInfo.getCodeMetadata()，这是内部 API → 缓解：JavaClass.getCodeInfo() 是公开 API，返回的 ICodeInfo 包含 metadata
- JadxArgs 有些选项类型复杂（Predicate、Path、IAliasProvider）不适合 CLI → 缓解：只暴露简单类型选项

---

### Task 1: 增强 AbstractCommand — 添加 15 个有价值的 JadxArgs 配置选项

**Depends on:** None
**Files:**
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/AbstractCommand.java:28-65`

- [ ] **Step 1: 修改 AbstractCommand 以添加 15 个新的 CLI 配置选项**

文件: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/AbstractCommand.java`

在现有 5 个选项之后，添加以下 15 个选项。同时修改 `run()` 方法中的 JadxArgs 配置逻辑。

```java
// 在现有 --include-resources 选项之后添加以下 15 个选项：

@Option(names = { "--use-imports" }, description = "Use import statements", defaultValue = "true")
protected boolean useImports = true;

@Option(names = { "--debug-info" }, description = "Include debug info in output", defaultValue = "true")
protected boolean debugInfo = true;

@Option(names = { "--inline-anonymous" }, description = "Inline anonymous classes", defaultValue = "true")
protected boolean inlineAnonymousClasses = true;

@Option(names = { "--inline-methods" }, description = "Inline methods", defaultValue = "true")
protected boolean inlineMethods = true;

@Option(names = { "--move-inner" }, description = "Move inner classes", defaultValue = "true")
protected boolean moveInnerClasses = true;

@Option(names = { "--extract-finally" }, description = "Extract finally blocks", defaultValue = "true")
protected boolean extractFinally = true;

@Option(names = { "--escape-unicode" }, description = "Escape unicode characters")
protected boolean escapeUnicode;

@Option(names = { "--replace-consts" }, description = "Replace constants", defaultValue = "true")
protected boolean replaceConsts = true;

@Option(names = { "--respect-bytecode-modifiers" }, description = "Respect bytecode access modifiers")
protected boolean respectBytecodeAccModifiers;

@Option(names = { "--deobf-min-length" }, description = "Minimum name length for deobfuscation", defaultValue = "0")
protected int deobfMinLength;

@Option(names = { "--deobf-max-length" }, description = "Maximum name length for deobfuscation")
protected int deobfMaxLength = Integer.MAX_VALUE;

@Option(names = { "--integer-format" }, description = "Integer format: AUTO, DEC, HEX, OCT", defaultValue = "AUTO")
protected String integerFormat;

@Option(names = { "--threads-count" }, description = "Number of processing threads", defaultValue = "-1")
protected int threadsCount = -1;

@Option(names = { "--class-filter" }, description = "Class name filter (regex)")
protected String classFilter;

@Option(names = { "--include-dependencies" }, description = "Include dependencies for filtered classes")
protected boolean includeDependencies;
```

修改 `run()` 方法中 JadxArgs 配置部分，在现有配置之后添加：

```java
// 在 args.setUsageInfoCache(new EmptyUsageInfoCache()); 之后添加：
args.setUseImports(useImports);
args.setDebugInfo(debugInfo);
args.setInlineAnonymousClasses(inlineAnonymousClasses);
args.setInlineMethods(inlineMethods);
args.setMoveInnerClasses(moveInnerClasses);
args.setExtractFinally(extractFinally);
args.setEscapeUnicode(escapeUnicode);
args.setReplaceConsts(replaceConsts);
args.setRespectBytecodeAccModifiers(respectBytecodeAccModifiers);
args.setDeobfuscationMinLength(deobfMinLength);
args.setDeobfuscationMaxLength(deobfMaxLength);
args.setIntegerFormat(jadx.api.args.IntegerFormat.valueOf(integerFormat.toUpperCase()));
if (threadsCount > 0) {
    args.setThreadsCount(threadsCount);
}
if (classFilter != null) {
    args.setClassFilter(s -> s.matches(classFilter));
}
args.setIncludeDependencies(includeDependencies);
```

- [ ] **Step 2: 验证 AbstractCommand 编译通过**
Run: `JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :jadx-ai-cli:spotlessApply :jadx-ai-cli:compileJava 2>&1 | tail -5`
Expected:
  - Exit code: 0
  - Output contains: "BUILD SUCCESSFUL"

- [ ] **Step 3: 提交**
Run: `git add jadx-ai-cli/src/main/java/jadx/ai/cli/commands/AbstractCommand.java && git commit -m "feat(cli): add 15 jadx configuration options to AbstractCommand"`

---

### Task 2: 创建 PackageDetailCommand — 包详情命令

**Depends on:** Task 1
**Files:**
- Create: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/PackageDetailCommand.java`

- [ ] **Step 1: 创建 PackageDetailCommand — 暴露 JavaPackage 的全部能力**

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
import jadx.api.JavaPackage;

@Command(name = "package-detail", description = "Get detailed package structure (sub-packages, classes, raw names)")
public class PackageDetailCommand extends AbstractCommand {

    @Option(names = { "-p", "--package" }, description = "Package name (full name)", required = true)
    protected String packageName;

    @Override
    protected Object execute(JadxDecompiler decompiler) throws Exception {
        JavaPackage targetPkg = null;
        for (JavaPackage pkg : decompiler.getPackages()) {
            if (pkg.getFullName().equals(packageName)) {
                targetPkg = pkg;
                break;
            }
        }
        if (targetPkg == null) {
            List<String> suggestions = decompiler.getPackages()
                    .stream()
                    .map(JavaPackage::getFullName)
                    .filter(n -> n.contains(packageName))
                    .collect(Collectors.toList());
            return JsonOutput.error("PackageNotFound",
                    "Package not found: " + packageName + ". Similar: " + suggestions);
        }

        PackageDetail detail = new PackageDetail();
        detail.name = targetPkg.getName();
        detail.fullName = targetPkg.getFullName();
        detail.rawName = targetPkg.getRawName();
        detail.rawFullName = targetPkg.getRawFullName();
        detail.isRoot = targetPkg.isRoot();
        detail.isLeaf = targetPkg.isLeaf();
        detail.isDefault = targetPkg.isDefault();

        detail.subPackages = new ArrayList<>();
        for (JavaPackage sub : targetPkg.getSubPackages()) {
            SubPackageInfo subInfo = new SubPackageInfo();
            subInfo.name = sub.getName();
            subInfo.fullName = sub.getFullName();
            subInfo.classCount = sub.getClasses().size();
            detail.subPackages.add(subInfo);
        }

        detail.classes = new ArrayList<>();
        for (JavaClass cls : targetPkg.getClasses()) {
            ClassInfo clsInfo = new ClassInfo();
            clsInfo.fullName = cls.getFullName();
            clsInfo.simpleName = cls.getName();
            clsInfo.isInner = cls.isInner();
            clsInfo.accessStr = cls.getAccessInfo().toString();
            detail.classes.add(clsInfo);
        }

        detail.classCount = targetPkg.getClasses().size();
        detail.classCountNoDup = targetPkg.getClassesNoDup().size();

        return JsonOutput.ok(detail);
    }

    static class PackageDetail {
        String name;
        String fullName;
        String rawName;
        String rawFullName;
        boolean isRoot;
        boolean isLeaf;
        boolean isDefault;
        List<SubPackageInfo> subPackages;
        List<ClassInfo> classes;
        int classCount;
        int classCountNoDup;
    }

    static class SubPackageInfo {
        String name;
        String fullName;
        int classCount;
    }

    static class ClassInfo {
        String fullName;
        String simpleName;
        boolean isInner;
        String accessStr;
    }
}
```

- [ ] **Step 2: 注册 PackageDetailCommand 到 JadxAICLI**
文件: `jadx-ai-cli/src/main/java/jadx/ai/cli/JadxAICLI.java`

在现有 subcommands 注册列表中添加 `PackageDetailCommand.class`。

- [ ] **Step 3: 验证编译**
Run: `JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :jadx-ai-cli:spotlessApply :jadx-ai-cli:compileJava 2>&1 | tail -5`
Expected:
  - Exit code: 0
  - Output contains: "BUILD SUCCESSFUL"

- [ ] **Step 4: 提交**
Run: `git add jadx-ai-cli/src/main/java/jadx/ai/cli/commands/PackageDetailCommand.java jadx-ai-cli/src/main/java/jadx/ai/cli/JadxAICLI.java && git commit -m "feat(cli): add package-detail command exposing JavaPackage full API"`

---

### Task 3: 创建 LineMapCommand — 行号映射 + 代码注解命令

**Depends on:** Task 1
**Files:**
- Create: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/LineMapCommand.java`

- [ ] **Step 1: 创建 LineMapCommand — 暴露源码行号映射和代码位置注解**

```java
package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.ICodeInfo;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.api.JavaNode;
import jadx.api.metadata.ICodeAnnotation;

@Command(name = "line-map", description = "Get decompiled-to-source line mapping and code annotations")
public class LineMapCommand extends AbstractCommand {

    @Option(names = { "-c", "--class" }, description = "Full class name", required = true)
    protected String className;

    @Option(names = { "--annotations" }, description = "Include code annotations (node refs at each position)")
    protected boolean includeAnnotations;

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

        ICodeInfo codeInfo = cls.getCodeInfo();
        LineMapResult result = new LineMapResult();
        result.className = cls.getFullName();

        // Source line mapping: decompiled line -> source line
        Map<Integer, Integer> lineMapping = codeInfo.getCodeMetadata().getLineMapping();
        result.lineMap = new ArrayList<>();
        for (Map.Entry<Integer, Integer> entry : lineMapping.entrySet()) {
            LineMapping lm = new LineMapping();
            lm.decompiledLine = entry.getKey();
            lm.sourceLine = entry.getValue();
            result.lineMap.add(lm);
        }

        // Code annotations at each position
        if (includeAnnotations) {
            result.annotations = new ArrayList<>();
            Map<Integer, ICodeAnnotation> annMap = codeInfo.getCodeMetadata().getAsMap();
            for (Map.Entry<Integer, ICodeAnnotation> entry : annMap.entrySet()) {
                AnnotationInfo annInfo = new AnnotationInfo();
                annInfo.position = entry.getKey();
                annInfo.type = entry.getValue().getAnnType().name();
                JavaNode node = decompiler.getJavaNodeByCodeAnnotation(codeInfo, entry.getValue());
                if (node != null) {
                    annInfo.nodeFullName = node.getFullName();
                    annInfo.nodeType = getNodeType(node);
                }
                result.annotations.add(annInfo);
            }
        }

        return JsonOutput.ok(result);
    }

    private String getNodeType(JavaNode node) {
        if (node instanceof JavaClass) {
            return "class";
        }
        if (node instanceof jadx.api.JavaMethod) {
            return "method";
        }
        if (node instanceof jadx.api.JavaField) {
            return "field";
        }
        if (node instanceof jadx.api.JavaVariable) {
            return "variable";
        }
        if (node instanceof jadx.api.JavaPackage) {
            return "package";
        }
        return "unknown";
    }

    static class LineMapResult {
        String className;
        List<LineMapping> lineMap;
        List<AnnotationInfo> annotations;
    }

    static class LineMapping {
        int decompiledLine;
        int sourceLine;
    }

    static class AnnotationInfo {
        int position;
        String type;
        String nodeFullName;
        String nodeType;
    }
}
```

- [ ] **Step 2: 注册 LineMapCommand 到 JadxAICLI**
文件: `jadx-ai-cli/src/main/java/jadx/ai/cli/JadxAICLI.java`

在现有 subcommands 注册列表中添加 `LineMapCommand.class`。

- [ ] **Step 3: 验证编译**
Run: `JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :jadx-ai-cli:spotlessApply :jadx-ai-cli:compileJava 2>&1 | tail -5`
Expected:
  - Exit code: 0
  - Output contains: "BUILD SUCCESSFUL"

- [ ] **Step 4: 提交**
Run: `git add jadx-ai-cli/src/main/java/jadx/ai/cli/commands/LineMapCommand.java jadx-ai-cli/src/main/java/jadx/ai/cli/JadxAICLI.java && git commit -m "feat(cli): add line-map command for source line mapping and code annotations"`

---

### Task 4: 增强 ClassDetailCommand — 添加 dependencies, codeParent, isNoCode

**Depends on:** Task 1
**Files:**
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/ClassDetailCommand.java:43-109`

- [ ] **Step 1: 修改 ClassDetailCommand 以添加未暴露的 JavaClass API**

文件: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/ClassDetailCommand.java`

在 ClassDetail 内部类中添加新字段：

```java
// 在 ClassDetail 类中添加以下字段（在 fields 之后）：
List<String> dependencies;
int totalDepsCount;
String codeParent;
String originalTopParentClass;
boolean isNoCode;
```

在 execute() 方法中，在 `detail.fields` 赋值之后添加：

```java
// Dependencies
detail.dependencies = new ArrayList<>();
for (JavaClass dep : cls.getDependencies()) {
    detail.dependencies.add(dep.getFullName());
}
detail.totalDepsCount = cls.getTotalDepsCount();

// Code parent and original top parent
if (cls.getCodeParent() != null) {
    detail.codeParent = cls.getCodeParent().getFullName();
}
detail.originalTopParentClass = cls.getOriginalTopParentClass().getFullName();
detail.isNoCode = cls.isNoCode();
```

- [ ] **Step 2: 验证编译**
Run: `JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :jadx-ai-cli:spotlessApply :jadx-ai-cli:compileJava 2>&1 | tail -5`
Expected:
  - Exit code: 0
  - Output contains: "BUILD SUCCESSFUL"

- [ ] **Step 3: 提交**
Run: `git add jadx-ai-cli/src/main/java/jadx/ai/cli/commands/ClassDetailCommand.java && git commit -m "feat(cli): enhance class-detail with dependencies, codeParent, isNoCode"`

---

### Task 5: 增强 UsageCommand — 添加 overrideRelatedMethods, unresolvedUsed, callsSelf, dependencies

**Depends on:** Task 1
**Files:**
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/UsageCommand.java`

- [ ] **Step 1: 修改 UsageCommand 以添加 overrideRelatedMethods 和 callsSelf**

文件: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/UsageCommand.java`

在 UsageResult 内部类中添加新字段：

```java
// 在 UsageResult 类中添加：
List<String> overrideRelatedMethods;
boolean callsSelf;
```

在 queryMethodUsage() 方法中，在 `result.references = refs;` 之后添加：

```java
// Override related methods
result.overrideRelatedMethods = new ArrayList<>();
for (JavaMethod overrideMth : mth.getOverrideRelatedMethods()) {
    result.overrideRelatedMethods.add(overrideMth.getFullName());
}
result.callsSelf = mth.callsSelf();
```

- [ ] **Step 2: 验证编译**
Run: `JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :jadx-ai-cli:spotlessApply :jadx-ai-cli:compileJava 2>&1 | tail -5`
Expected:
  - Exit code: 0
  - Output contains: "BUILD SUCCESSFUL"

- [ ] **Step 3: 提交**
Run: `git add jadx-ai-cli/src/main/java/jadx/ai/cli/commands/UsageCommand.java && git commit -m "feat(cli): enhance usage command with overrideRelatedMethods and callsSelf"`

---

### Task 6: 增强 Search/List/Resources/Decompile 命令

**Depends on:** Task 1
**Files:**
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/SearchCommand.java`
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/ListCommand.java`
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/ResourcesCommand.java`
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/DecompileCommand.java`

- [ ] **Step 1: 增强 SearchCommand — 添加 alias 搜索模式**

文件: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/SearchCommand.java`

在 searchType switch 中添加 "alias" case：

```java
// 在 switch 中添加 alias case（在 "string" 之后）：
case "alias":
    return searchByAlias(decompiler);
```

添加 searchByAlias 方法：

```java
private Object searchByAlias(JadxDecompiler decompiler) {
    List<ClassSearchResult> results = new ArrayList<>();
    jadx.api.JavaClass aliasCls = decompiler.searchJavaClassByAliasFullName(query);
    if (aliasCls != null) {
        ClassSearchResult r = new ClassSearchResult();
        r.fullName = aliasCls.getFullName();
        r.simpleName = aliasCls.getName();
        r.packageName = aliasCls.getPackage();
        results.add(r);
    }
    return JsonOutput.list(results);
}
```

更新 searchType 选项描述：

```java
// 将 searchType 选项描述改为：
@Option(names = { "-t", "--type" }, description = "Search type: class, method, field, string, alias", required = true)
```

更新 error message：

```java
// 将 error message 改为：
"Unknown search type: " + searchType + ". Use: class, method, field, string, alias"
```

- [ ] **Step 2: 增强 ListCommand — 添加 packages 详细模式**

文件: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/ListCommand.java`

修改 listPackages 方法，当 `-v` (verbose) 选项启用时返回详细包信息：

添加 verbose 选项：

```java
@Option(names = { "-v", "--verbose" }, description = "Show detailed information")
protected boolean verbose;
```

修改 listPackages 方法：

```java
private Object listPackages(JadxDecompiler decompiler) {
    if (verbose) {
        List<PackageDetailInfo> results = new ArrayList<>();
        for (jadx.api.JavaPackage pkg : decompiler.getPackages()) {
            if (packageName != null && !pkg.getFullName().startsWith(packageName)) {
                continue;
            }
            PackageDetailInfo info = new PackageDetailInfo();
            info.fullName = pkg.getFullName();
            info.name = pkg.getName();
            info.rawName = pkg.getRawName();
            info.rawFullName = pkg.getRawFullName();
            info.classCount = pkg.getClasses().size();
            info.isLeaf = pkg.isLeaf();
            info.subPackageCount = pkg.getSubPackages().size();
            results.add(info);
        }
        return JsonOutput.list(results);
    }
    // 现有简单模式保持不变
    List<String> packages = decompiler.getPackages()
            .stream()
            .map(pkg -> pkg.getName())
            .filter(p -> packageName == null || p.startsWith(packageName))
            .sorted()
            .collect(Collectors.toList());
    return JsonOutput.list(packages);
}
```

添加 PackageDetailInfo 内部类：

```java
static class PackageDetailInfo {
    String fullName;
    String name;
    String rawName;
    String rawFullName;
    int classCount;
    boolean isLeaf;
    int subPackageCount;
}
```

- [ ] **Step 3: 增强 ResourcesCommand — 添加 deobfName**

文件: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/ResourcesCommand.java`

在 ResourceInfo 内部类中添加 deobfName 字段：

```java
// 在 ResourceInfo 类中添加：
String deobfName;
```

在 execute() 方法中，在 `info.type = res.getType().name();` 之后添加：

```java
info.deobfName = res.getDeobfName();
```

- [ ] **Step 4: 增强 DecompileCommand — 添加 sourceLine mapping**

文件: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/DecompileCommand.java`

添加 `--line-map` 选项：

```java
@Option(names = { "--line-map" }, description = "Include decompiled-to-source line mapping")
protected boolean includeLineMap;
```

在 DecompileResult 内部类中添加：

```java
Map<Integer, Integer> sourceLineMap;
```

在 decompileClass() 方法中，在 `result.sourceCode = cls.getCode();` 之后添加：

```java
if (includeLineMap) {
    result.sourceLineMap = cls.getCodeInfo().getCodeMetadata().getLineMapping();
}
```

- [ ] **Step 5: 验证编译**
Run: `JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :jadx-ai-cli:spotlessApply :jadx-ai-cli:compileJava 2>&1 | tail -5`
Expected:
  - Exit code: 0
  - Output contains: "BUILD SUCCESSFUL"

- [ ] **Step 6: 提交**
Run: `git add jadx-ai-cli/src/main/java/jadx/ai/cli/commands/SearchCommand.java jadx-ai-cli/src/main/java/jadx/ai/cli/commands/ListCommand.java jadx-ai-cli/src/main/java/jadx/ai/cli/commands/ResourcesCommand.java jadx-ai-cli/src/main/java/jadx/ai/cli/commands/DecompileCommand.java && git commit -m "feat(cli): enhance search, list, resources, decompile commands with missing API capabilities"`

---

### Task 7: 更新 Skills + 测试 + 完整构建验证

**Depends on:** Task 2, Task 3, Task 4, Task 5, Task 6
**Files:**
- Create: `.claude/skills/jadx-package-detail.md`
- Create: `.claude/skills/jadx-line-map.md`
- Modify: `.claude/skills/jadx-class-detail.md`
- Modify: `.claude/skills/jadx-usage.md`
- Modify: `.claude/skills/jadx-search.md`
- Modify: `.claude/skills/jadx-list.md`
- Modify: `.claude/skills/jadx-resources.md`
- Modify: `.claude/skills/jadx-decompile.md`
- Modify: `.claude/skills/jadx-analyze.md`
- Modify: `jadx-ai-cli/src/test/java/jadx/ai/cli/CommandsTest.java`

- [ ] **Step 1: 创建 jadx-package-detail skill**

```markdown
---
name: jadx-package-detail
description: Get detailed package structure from Android APK using JADX AI-CLI. Includes sub-packages, classes, raw names, leaf/root status.
---

# JADX Package Detail Skill

Get detailed package structure information including sub-packages, classes, raw names, and leaf/root status.

## Usage

When the user asks about package structure, sub-packages, or package hierarchy:

1. Run the JADX AI-CLI package-detail command
2. Present the structured results

## Command

```bash
jadx-ai package-detail -p <package-name> <input-file>
```

## Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `<input-file>` | Yes | Path to APK, DEX file |
| `-p, --package` | Yes | Full package name |

## Examples

```bash
# Get package details
jadx-ai package-detail -p com.example.app app.apk

# Get default package details
jadx-ai package-detail -p "" app.apk
```
```

- [ ] **Step 2: 创建 jadx-line-map skill**

```markdown
---
name: jadx-line-map
description: Get decompiled-to-source line mapping and code annotations from Android APK using JADX AI-CLI. Maps decompiled line numbers back to original source lines.
---

# JADX Line Map Skill

Get decompiled-to-source line mapping and code position annotations.

## Usage

When the user asks about line number mapping, source line tracing, or code annotations at positions:

1. Run the JADX AI-CLI line-map command
2. Present the structured results

## Command

```bash
jadx-ai line-map -c <class-name> [--annotations] <input-file>
```

## Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `<input-file>` | Yes | Path to APK, DEX file |
| `-c, --class` | Yes | Full class name |
| `--annotations` | No | Include code annotations (node refs at each position) |

## Examples

```bash
# Get line mapping
jadx-ai line-map -c com.example.MyClass app.apk

# Get line mapping with annotations
jadx-ai line-map -c com.example.MyClass --annotations app.apk
```
```

- [ ] **Step 3: 更新现有 Skills 文件以反映增强**

更新 jadx-class-detail.md — 添加 dependencies, codeParent, isNoCode 到输出格式描述
更新 jadx-usage.md — 添加 overrideRelatedMethods, callsSelf 到输出格式描述
更新 jadx-search.md — 添加 alias 搜索类型
更新 jadx-list.md — 添加 -v verbose 选项
更新 jadx-resources.md — 添加 deobfName 字段
更新 jadx-decompile.md — 添加 --line-map 选项
更新 jadx-analyze.md — 添加 package-detail 和 line-map 步骤

- [ ] **Step 4: 添加测试用例到 CommandsTest**

文件: `jadx-ai-cli/src/test/java/jadx/ai/cli/CommandsTest.java`

添加 2 个新测试方法：testPackageDetailCommand, testLineMapCommand

- [ ] **Step 5: 完整构建验证**
Run: `JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :jadx-ai-cli:build 2>&1 | tail -10`
Expected:
  - Exit code: 0
  - Output contains: "BUILD SUCCESSFUL"

- [ ] **Step 6: 验证 CLI help 包含所有 11 个命令**
Run: `JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :jadx-ai-cli:run --args="help" 2>&1 | grep -E "Commands:|info|list|search|decompile|export|resources|usage|class-detail|script|package-detail|line-map"`
Expected:
  - Output contains all 11 command names

- [ ] **Step 7: 提交**
Run: `git add .claude/skills/ jadx-ai-cli/src/test/java/jadx/ai/cli/CommandsTest.java && git commit -m "feat(skills): add package-detail and line-map skills, update all skills for enhanced commands"`