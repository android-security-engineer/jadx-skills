# CLI Search Capability Enhancement Plan

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** 将 jadx-gui 的搜索能力缺口补齐到 CLI，包括 regex/忽略大小写/包过滤/名称变体/资源搜索/usage 递归/缓存恢复/缺失 Skills

**Architecture:** 用户通过 CLI 选项传入搜索参数 → SearchCommand 使用 JadxDecompiler 公共 API 遍历类/方法/字段/资源 → 新增的匹配逻辑（regex/ignoreCase）替代原有 `String.contains()` → 名称变体通过 `getClassNode().getClassInfo()` 等内部 API 获取 → 资源搜索复用 `decompiler.getResources()` + `loadContent()` → usage 递归通过循环调用 `getUseIn()` 实现 → 缓存恢复让 AbstractCommand 使用 JadxArgs 默认值而非 NoOp

**Tech Stack:** Java 11+, picocli 4.x, jadx-core (现有依赖), Gradle

**Scope:** Medium
**Risk:** Medium

**Risks:**
- Task 2 修改 SearchCommand 的匹配逻辑，需确保原有 substring/exact 行为不受影响 → 缓解：新选项均有默认值（regex=false, ignoreCase=false）
- Task 1 恢复内存缓存可能增大大型 APK 的内存占用 → 缓解：CLI 进程生命周期短，且 InMemoryCodeCache 是 jadx-core 默认行为
- Task 3 资源搜索对大文件可能耗时 → 缓解：添加 --max-size 选项跳过大文件

**Autonomy Level:** Full

---

### Task 1: 恢复 AbstractCommand 内存缓存 — 提升 CLI 单次调用性能

**Depends on:** None
**Files:**
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/AbstractCommand.java:180-181`

- [ ] **Step 1: 删除 NoOp 缓存配置 — 让 JadxArgs 使用默认的 InMemoryCodeCache 和 InMemoryUsageInfoCache**

文件: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/AbstractCommand.java:180-181`

删除以下两行：
```java
args.setCodeCache(new NoOpCodeCache());
args.setUsageInfoCache(new EmptyUsageInfoCache());
```

同时删除顶部对应的 import 语句（第 17-18 行）：
```java
import jadx.api.impl.NoOpCodeCache;
import jadx.api.usage.impl.EmptyUsageInfoCache;
```

- [ ] **Step 2: 验证编译通过**
Run: `cd /data/local/tmp/workspace/github/AI-jadx && ./gradlew :jadx-ai-cli:compileJava 2>&1 | tail -5`
Expected:
  - Exit code: 0
  - Output does NOT contain: "error" or "FAIL"

- [ ] **Step 3: 提交**
Run: `git add jadx-ai-cli/src/main/java/jadx/ai/cli/commands/AbstractCommand.java && git commit -m "feat(jadx-ai-cli): restore default InMemoryCodeCache and InMemoryUsageInfoCache for better single-invocation performance"`

---

### Task 2: 增强 SearchCommand — 添加 regex/ignoreCase/包过滤/名称变体

**Depends on:** None
**Files:**
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/SearchCommand.java`

- [ ] **Step 1: 添加新 CLI 选项 — regex、ignoreCase、package 过滤**

文件: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/SearchCommand.java`

在现有选项声明之后（`searchParent` 之后），添加新选项：

```java
@Option(names = { "--regex" }, description = "Use regex matching instead of substring")
protected boolean regex;

@Option(names = { "-i", "--ignore-case" }, description = "Case-insensitive matching")
protected boolean ignoreCase;

@Option(names = { "-p", "--package" }, description = "Filter results by package name (substring match)")
protected String packageFilter;
```

- [ ] **Step 2: 替换 matches() 方法 — 支持 regex/ignoreCase/exact/substring 四种模式**

文件: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/SearchCommand.java:52-60`

替换 `matches` 方法为：

```java
private java.util.regex.Pattern pattern;

private boolean matches(String text) {
    if (text == null) {
        return false;
    }
    String input = ignoreCase ? text.toLowerCase() : text;
    String q = ignoreCase ? query.toLowerCase() : query;
    if (regex) {
        if (pattern == null) {
            int flags = ignoreCase ? java.util.regex.Pattern.CASE_INSENSITIVE : 0;
            pattern = java.util.regex.Pattern.compile(query, flags);
        }
        return pattern.matcher(text).find();
    }
    if (exact) {
        return input.equals(q);
    }
    return input.contains(q);
}
```

- [ ] **Step 3: 添加包过滤辅助方法**

在 `matches` 方法之后添加：

```java
private boolean matchesPackage(JavaClass cls) {
    if (packageFilter == null) {
        return true;
    }
    String pkg = cls.getPackage();
    if (pkg == null) {
        return false;
    }
    return ignoreCase ? pkg.toLowerCase().contains(packageFilter.toLowerCase())
            : pkg.contains(packageFilter);
}
```

- [ ] **Step 4: 扩展 searchClasses — 搜索 aliasFullName 和 rawName 名称变体，添加包过滤**

文件: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/SearchCommand.java:62-88`

替换 `searchClasses` 方法为：

```java
private Object searchClasses(JadxDecompiler decompiler) {
    List<ClassSearchResult> results = new ArrayList<>();
    if (searchParent) {
        JavaClass cls = decompiler.searchJavaClassOrItsParentByOrigFullName(query);
        if (cls != null) {
            ClassSearchResult r = new ClassSearchResult();
            r.fullName = cls.getFullName();
            r.simpleName = cls.getName();
            r.packageName = cls.getPackage();
            r.rawName = cls.getRawName();
            results.add(r);
        }
        return JsonOutput.list(results);
    }
    for (JavaClass cls : decompiler.getClasses()) {
        if (!matchesPackage(cls)) {
            continue;
        }
        if (matches(cls.getFullName()) || matches(cls.getName())
                || matches(cls.getRawName())) {
            ClassSearchResult r = new ClassSearchResult();
            r.fullName = cls.getFullName();
            r.simpleName = cls.getName();
            r.packageName = cls.getPackage();
            r.rawName = cls.getRawName();
            results.add(r);
            if (results.size() >= limit) {
                break;
            }
        }
    }
    return JsonOutput.list(results);
}
```

- [ ] **Step 5: 扩展 searchMethods — 搜索 alias 和 fullId 名称变体，添加包过滤**

文件: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/SearchCommand.java:90-110`

替换 `searchMethods` 方法为：

```java
private Object searchMethods(JadxDecompiler decompiler) {
    List<MethodSearchResult> results = new ArrayList<>();
    for (JavaClass cls : decompiler.getClasses()) {
        if (!matchesPackage(cls)) {
            continue;
        }
        for (JavaMethod m : cls.getMethods()) {
            if (matches(m.getName()) || matches(m.getFullName())) {
                MethodSearchResult r = new MethodSearchResult();
                r.className = cls.getFullName();
                r.methodName = m.getName();
                r.returnType = m.getReturnType().toString();
                r.fullId = m.getFullName();
                results.add(r);
                if (results.size() >= limit) {
                    break;
                }
            }
        }
        if (results.size() >= limit) {
            break;
        }
    }
    return JsonOutput.list(results);
}
```

- [ ] **Step 6: 扩展 searchFields — 搜索 alias 和 fullId 名称变体，添加包过滤**

文件: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/SearchCommand.java:112-132`

替换 `searchFields` 方法为：

```java
private Object searchFields(JadxDecompiler decompiler) {
    List<FieldSearchResult> results = new ArrayList<>();
    for (JavaClass cls : decompiler.getClasses()) {
        if (!matchesPackage(cls)) {
            continue;
        }
        for (JavaField f : cls.getFields()) {
            if (matches(f.getName()) || matches(f.getFullName())
                    || matches(f.getRawName())) {
                FieldSearchResult r = new FieldSearchResult();
                r.className = cls.getFullName();
                r.fieldName = f.getName();
                r.type = f.getType().toString();
                r.rawName = f.getRawName();
                results.add(r);
                if (results.size() >= limit) {
                    break;
                }
            }
        }
        if (results.size() >= limit) {
            break;
        }
    }
    return JsonOutput.list(results);
}
```

- [ ] **Step 7: 扩展结果类 — 添加 rawName/fullId 字段**

替换结果类定义：

```java
static class ClassSearchResult {
    String fullName;
    String simpleName;
    String packageName;
    String rawName;
}

static class MethodSearchResult {
    String className;
    String methodName;
    String returnType;
    String fullId;
}

static class FieldSearchResult {
    String className;
    String fieldName;
    String type;
    String rawName;
}

static class StringSearchResult {
    String className;
    String matchingLine;
}
```

- [ ] **Step 8: 验证编译通过**
Run: `cd /data/local/tmp/workspace/github/AI-jadx && ./gradlew :jadx-ai-cli:compileJava 2>&1 | tail -5`
Expected:
  - Exit code: 0
  - Output does NOT contain: "error" or "FAIL"

- [ ] **Step 9: 提交**
Run: `git add jadx-ai-cli/src/main/java/jadx/ai/cli/commands/SearchCommand.java && git commit -m "feat(jadx-ai-cli): add regex, ignoreCase, package filter, and name variant search to search command"`

---

### Task 3: 添加资源内容搜索 — search --type resource

**Depends on:** Task 2
**Files:**
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/SearchCommand.java`

- [ ] **Step 1: 添加 resource 搜索类型和选项**

在 SearchCommand 选项区域添加资源搜索相关选项（在 `packageFilter` 之后）：

```java
@Option(names = { "--resource-type" }, description = "Filter resource search by type: MANIFEST, XML, ARSC, IMG, FONT, JSON, TEXT, HTML, LIB, CODE, APK, ARCHIVE, VIDEOS, SOUNDS")
protected String resourceTypeFilter;

@Option(names = { "--max-size" }, description = "Max resource file size in KB to search (default: 512)", defaultValue = "512")
protected int maxResourceSizeKB;
```

- [ ] **Step 2: 添加 resource case 到 execute switch**

在 `execute` 方法的 switch 中，在 `case "alias"` 之前添加：

```java
case "resource":
    return searchResources(decompiler);
```

- [ ] **Step 3: 添加 searchResources 方法**

在 `searchByAlias` 方法之后添加：

```java
private Object searchResources(JadxDecompiler decompiler) {
    List<ResourceSearchResult> results = new ArrayList<>();
    for (var res : decompiler.getResources()) {
        if (resourceTypeFilter != null) {
            try {
                jadx.api.ResourceType filterType = jadx.api.ResourceType.valueOf(resourceTypeFilter.toUpperCase());
                if (res.getType() != filterType) {
                    continue;
                }
            } catch (IllegalArgumentException e) {
                return JsonOutput.error("InvalidResourceType",
                        "Unknown resource type: " + resourceTypeFilter);
            }
        }
        String resName = res.getOriginalName();
        if (!matches(resName) && !matches(res.getDeobfName())) {
            continue;
        }
        ResourceSearchResult r = new ResourceSearchResult();
        r.name = resName;
        r.type = res.getType().name();
        r.deobfName = res.getDeobfName();
        try {
            var container = res.loadContent();
            if (container != null) {
                String text = container.getText().toString();
                if (text.length() > maxResourceSizeKB * 1024) {
                    r.matchingSnippet = "Resource too large (" + (text.length() / 1024) + "KB), skipped. Use --max-size to increase.";
                } else {
                    List<String> matchingLines = new ArrayList<>();
                    for (String line : text.split("\n")) {
                        if (matches(line)) {
                            matchingLines.add(line.trim());
                            if (matchingLines.size() >= 10) {
                                break;
                            }
                        }
                    }
                    if (!matchingLines.isEmpty() || regex || exact) {
                        r.matchingLines = matchingLines;
                    }
                }
            }
        } catch (Exception e) {
            r.matchingSnippet = "Error reading resource: " + e.getMessage();
        }
        results.add(r);
        if (results.size() >= limit) {
            break;
        }
    }
    return JsonOutput.list(results);
}
```

- [ ] **Step 4: 添加 ResourceSearchResult 内部类**

在 `StringSearchResult` 类之后添加：

```java
static class ResourceSearchResult {
    String name;
    String type;
    String deobfName;
    List<String> matchingLines;
    String matchingSnippet;
}
```

- [ ] **Step 5: 更新 searchType 描述**

将 `@Option` 的 description 从 `"Search type: class, method, field, string, alias"` 更新为：

```java
@Option(names = { "-t", "--type" }, description = "Search type: class, method, field, string, alias, resource", required = true)
```

- [ ] **Step 6: 验证编译通过**
Run: `cd /data/local/tmp/workspace/github/AI-jadx && ./gradlew :jadx-ai-cli:compileJava 2>&1 | tail -5`
Expected:
  - Exit code: 0
  - Output does NOT contain: "error" or "FAIL"

- [ ] **Step 7: 提交**
Run: `git add jadx-ai-cli/src/main/java/jadx/ai/cli/commands/SearchCommand.java && git commit -m "feat(jadx-ai-cli): add resource content search with type filter and size limit"`

---

### Task 4: 增强 UsageCommand — 添加递归调用链探索

**Depends on:** None
**Files:**
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/UsageCommand.java`

- [ ] **Step 1: 添加 --depth 选项**

在 UsageCommand 的选项声明区域（`queryType` 之后）添加：

```java
@Option(names = { "-d", "--depth" }, description = "Recursion depth for usage exploration (1=flat, 2+=recursive, default: 1)", defaultValue = "1")
protected int depth;
```

- [ ] **Step 2: 添加递归查询方法**

在 `getNodeType` 方法之后添加：

```java
private UsageRef buildUsageRef(JavaNode node) {
    UsageRef ref = new UsageRef();
    ref.name = node.getFullName();
    ref.nodeType = getNodeType(node);
    return ref;
}

private void collectUsageRecursive(JavaNode node, int currentDepth, UsageTreeRef parent) {
    List<JavaNode> nodes;
    if (node instanceof JavaMethod) {
        nodes = "used".equals(queryType) ? ((JavaMethod) node).getUsed() : node.getUseIn();
    } else {
        nodes = "used".equals(queryType) ? new ArrayList<>() : node.getUseIn();
    }
    for (JavaNode child : nodes) {
        UsageTreeRef childRef = new UsageTreeRef();
        childRef.name = child.getFullName();
        childRef.nodeType = getNodeType(child);
        if (currentDepth < depth) {
            collectUsageRecursive(child, currentDepth + 1, childRef);
        }
        parent.children.add(childRef);
    }
}
```

- [ ] **Step 3: 添加 UsageTreeRef 内部类**

在 `UsageRef` 类之后添加：

```java
static class UsageTreeRef {
    String name;
    String nodeType;
    List<UsageTreeRef> children = new ArrayList<>();
}
```

- [ ] **Step 4: 修改 queryMethodUsage 支持递归**

文件: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/UsageCommand.java:90-123`

替换 `queryMethodUsage` 方法为：

```java
private Object queryMethodUsage(JavaClass cls, String mthName) {
    cls.getCode();
    List<JavaMethod> methods = cls.getMethods()
            .stream()
            .filter(m -> m.getName().equals(mthName))
            .collect(Collectors.toList());
    if (methods.isEmpty()) {
        return JsonOutput.error("MethodNotFound", "Method not found: " + mthName);
    }
    JavaMethod mth = methods.get(0);

    if (depth > 1) {
        UsageTreeResult result = new UsageTreeResult();
        result.target = mth.getFullName();
        result.targetType = "method";
        result.queryType = queryType;
        result.depth = depth;
        UsageTreeRef rootRef = new UsageTreeRef();
        rootRef.name = mth.getFullName();
        rootRef.nodeType = "method";
        collectUsageRecursive(mth, 1, rootRef);
        result.usageTree = rootRef.children;
        result.overrideRelatedMethods = new ArrayList<>();
        for (JavaMethod override : mth.getOverrideRelatedMethods()) {
            result.overrideRelatedMethods.add(override.getFullName());
        }
        result.callsSelf = mth.callsSelf();
        return JsonOutput.ok(result);
    }

    List<UsageRef> refs = new ArrayList<>();
    List<JavaNode> nodes = "used".equals(queryType) ? mth.getUsed() : mth.getUseIn();
    for (JavaNode node : nodes) {
        refs.add(buildUsageRef(node));
    }
    UsageResult result = new UsageResult();
    result.target = mth.getFullName();
    result.targetType = "method";
    result.queryType = queryType;
    result.references = refs;
    result.overrideRelatedMethods = new ArrayList<>();
    for (JavaMethod override : mth.getOverrideRelatedMethods()) {
        result.overrideRelatedMethods.add(override.getFullName());
    }
    result.callsSelf = mth.callsSelf();
    result.unresolvedUsed = new ArrayList<>();
    for (jadx.api.plugins.input.data.IMethodRef ref : mth.getUnresolvedUsed()) {
        result.unresolvedUsed.add(ref.toString());
    }
    return JsonOutput.ok(result);
}
```

- [ ] **Step 5: 添加 UsageTreeResult 内部类**

在 `UsageResult` 类之后添加：

```java
static class UsageTreeResult {
    String target;
    String targetType;
    String queryType;
    int depth;
    List<UsageTreeRef> usageTree;
    List<String> overrideRelatedMethods;
    boolean callsSelf;
}
```

- [ ] **Step 6: 验证编译通过**
Run: `cd /data/local/tmp/workspace/github/AI-jadx && ./gradlew :jadx-ai-cli:compileJava 2>&1 | tail -5`
Expected:
  - Exit code: 0
  - Output does NOT contain: "error" or "FAIL"

- [ ] **Step 7: 提交**
Run: `git add jadx-ai-cli/src/main/java/jadx/ai/cli/commands/UsageCommand.java && git commit -m "feat(jadx-ai-cli): add recursive usage exploration with --depth option"`

---

### Task 5: 创建缺失的 Skills 文档 — rename/reload/script

**Depends on:** None
**Files:**
- Create: `.claude/skills/jadx-rename.md`
- Create: `.claude/skills/jadx-reload.md`
- Create: `.claude/skills/jadx-script.md`

- [ ] **Step 1: 创建 jadx-rename.md skill 文件**

```markdown
---
name: jadx-rename
description: Rename classes, methods, fields, or packages in Android APK/DEX files using JADX AI-CLI. Returns structured JSON results.
---

# JADX Rename Skill

Rename classes, methods, fields, or packages in decompiled code to apply meaningful names.

## Usage

1. Identify the target to rename (class, method, field, or package)
2. Run the JADX AI-CLI rename command with the target and new name
3. Present the confirmation result

## Command

```bash
jadx-ai rename -t <type> -n <new-name> [options] <input-file>
```

## Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `<input-file>` | Yes | APK, DEX, JAR, AAR, or class file |
| `-t, --type` | Yes | Target type: `class`, `method`, `field`, `package` |
| `-c, --class` | Conditional | Class full name (required for method/field rename) |
| `-m, --method` | No | Method name to rename (requires --class) |
| `-f, --field` | No | Field name to rename (requires --class) |
| `-p, --package` | No | Package full name to rename |
| `-n, --name` | No | New name (alias) to set. Omit with --remove-alias to revert |
| `--remove-alias` | No | Remove alias and revert to original name |

## Examples

```bash
# Rename a class
jadx-ai rename -t class -c "com.example.a" -n "MainActivity" app.apk

# Rename a method
jadx-ai rename -t method -c "com.example.MainActivity" -m "a" -n "onCreate" app.apk

# Rename a field
jadx-ai rename -t field -c "com.example.MainActivity" -f "b" -n "mTextView" app.apk

# Rename a package
jadx-ai rename -t package -p "com.example.a" -n "com.example.ui" app.apk

# Remove an alias (revert to original)
jadx-ai rename -t class -c "com.example.MainActivity" --remove-alias app.apk
```
```

- [ ] **Step 2: 创建 jadx-reload.md skill 文件**

```markdown
---
name: jadx-reload
description: Reload, recompile, or unload class code in Android APK/DEX files using JADX AI-CLI. Returns structured JSON results.
---

# JADX Reload Skill

Reload or unload decompiled class code, or refresh code data for updated analysis.

## Usage

1. Identify the class to reload or decide to reload all classes
2. Run the JADX AI-CLI reload command
3. Present the confirmation result

## Command

```bash
jadx-ai reload [options] <input-file>
```

## Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `<input-file>` | Yes | APK, DEX, JAR, AAR, or class file |
| `-c, --class` | No | Class full name to reload/unload |
| `-t, --type` | No | Action: `reload` (recompile class), `unload` (free code), `codedata` (refresh all code data). Default: `reload` |
| `--all` | No | Apply action to all classes |

## Examples

```bash
# Reload a specific class (recompile)
jadx-ai reload -c "com.example.MainActivity" app.apk

# Unload a specific class (free memory)
jadx-ai reload -c "com.example.MainActivity" -t unload app.apk

# Refresh all code data
jadx-ai reload --all -t codedata app.apk

# Reload all classes
jadx-ai reload --all app.apk
```
```

- [ ] **Step 3: 创建 jadx-script.md skill 文件**

```markdown
---
name: jadx-script
description: Run JavaScript scripts to operate on the JADX decompiler instance for Android APK/DEX files. Returns structured JSON results.
---

# JADX Script Skill

Run custom scripts that have direct access to the JadxDecompiler instance for advanced analysis or automation.

## Usage

1. Write a JavaScript file that uses the `decompiler` and `inputFile` variables
2. Run the JADX AI-CLI script command with the script file
3. Present the script output

## Command

```bash
jadx-ai script [options] <script-file> <input-file>
```

## Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `<script-file>` | Yes | Path to the JavaScript (.js) file |
| `<input-file>` | Yes | APK, DEX, JAR, AAR, or class file |
| `--engine` | No | Script engine: `js` (default) |

## Available Variables

| Variable | Type | Description |
|----------|------|-------------|
| `decompiler` | `JadxDecompiler` | The loaded decompiler instance with full API access |
| `inputFile` | `File` | The input file being analyzed |

## Examples

```bash
# Run a custom analysis script
jadx-ai script analyze.js app.apk

# Run with explicit engine
jadx-ai script --engine js custom.js app.apk
```
```

- [ ] **Step 4: 提交**
Run: `git add .claude/skills/jadx-rename.md .claude/skills/jadx-reload.md .claude/skills/jadx-script.md && git commit -m "docs(skills): add jadx-rename, jadx-reload, and jadx-script skill definitions"`

---

### Task 6: 更新现有 Skills 文档 — jadx-search 和 jadx-usage

**Depends on:** Task 2, Task 3, Task 4
**Files:**
- Modify: `.claude/skills/jadx-search.md`
- Modify: `.claude/skills/jadx-usage.md`

- [ ] **Step 1: 读取并更新 jadx-search.md — 添加新选项文档**

读取 `.claude/skills/jadx-search.md`，在 Parameters 表格中添加以下行：

| Parameter | Required | Description |
|-----------|----------|-------------|
| `--regex` | No | Use regex matching instead of substring |
| `-i, --ignore-case` | No | Case-insensitive matching |
| `-p, --package` | No | Filter results by package name (substring match) |
| `--resource-type` | No | Filter resource search by type (MANIFEST, XML, ARSC, etc.) |
| `--max-size` | No | Max resource file size in KB to search (default: 512) |

在 Search Types 表格中添加 resource 行：

| Type | Searches In | Result Fields |
|------|------------|---------------|
| `resource` | Resource file names and content | name, type, deobfName, matchingLines |

在 Examples 中添加示例：

```bash
# Regex search for onCreate methods
jadx-ai search -t method -q "onCreate.*View" --regex app.apk

# Case-insensitive class search
jadx-ai search -t class -q "activity" -i app.apk

# Search within a specific package
jadx-ai search -t class -q "handler" -p "com.example.network" app.apk

# Search resource content
jadx-ai search -t resource -q "android.permission" --resource-type MANIFEST app.apk
```

- [ ] **Step 2: 读取并更新 jadx-usage.md — 添加 --depth 文档**

读取 `.claude/skills/jadx-usage.md`，在 Parameters 表格中添加：

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-d, --depth` | No | Recursion depth for usage exploration (1=flat, 2+=recursive, default: 1) |

在 Examples 中添加示例：

```bash
# Recursive usage exploration (3 levels deep)
jadx-ai usage -c "com.example.NetworkClient" -m "sendRequest" --depth 3 app.apk

# Find what a method calls, recursively
jadx-ai usage -c "com.example.MainActivity" -m "onCreate" -t used --depth 2 app.apk
```

- [ ] **Step 3: 提交**
Run: `git add .claude/skills/jadx-search.md .claude/skills/jadx-usage.md && git commit -m "docs(skills): update jadx-search and jadx-usage skills with new options"`

---

### Task 7: 全量编译验证 + 最终提交

**Depends on:** Task 1, Task 2, Task 3, Task 4, Task 5, Task 6
**Files:**
- None (verification only)

- [ ] **Step 1: 全量编译验证**
Run: `cd /data/local/tmp/workspace/github/AI-jadx && ./gradlew :jadx-ai-cli:build 2>&1 | tail -10`
Expected:
  - Exit code: 0
  - Output contains: "BUILD SUCCESSFUL"

- [ ] **Step 2: 验证所有修改文件一致性**
Run: `cd /data/local/tmp/workspace/github/AI-jadx && git diff --stat HEAD~6`
Expected:
  - Shows changes in AbstractCommand.java, SearchCommand.java, UsageCommand.java, and skill files
  - No unexpected files modified

- [ ] **Step 3: 验证 CLI help 输出包含新选项**
Run: `cd /data/local/tmp/workspace/github/AI-jadx && java -jar jadx-ai-cli/build/libs/jadx-ai-cli-*.jar search --help 2>&1 | grep -E "(regex|ignore-case|package|resource)" `
Expected:
  - Output contains: "regex", "ignore-case", "package", "resource"
