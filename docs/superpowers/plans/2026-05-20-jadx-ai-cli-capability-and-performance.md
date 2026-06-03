# Feature: jadx-ai-cli 能力补齐与性能优化

**Goal:** 补齐 jadx-ai-cli 相对 jadx-gui 的核心缺失能力（注释、图生成、Hook 片段、入口导航），修复 daemon 已知 bug 并补全 daemon 命令注册，为连续调用场景提供缓存加速。

**Architecture:**
- 数据流：CLI 参数 → AbstractCommand.run() → [daemon 检测] → JadxDecompiler API → JSON 输出
- 关键组件：新增 CommentCommand、GraphCommand、HookCommand、NavigateCommand；修复 DaemonServer 字段映射；为 daemon 添加结果缓存
- 设计理由：新命令继承 AbstractCommand 获得统一的 daemon 自动检测和参数配置能力，daemon 端通过 DaemonCommandRegistry 扩展

**Tech Stack:** Java 11, picocli 4.7.5, Gson 2.10.1, JADX core API

**Scope:** Large

**Risk:** Medium — 修改 daemon 核心路由 + 新增多个命令

**Risks:**
- DaemonServer 中 executeDecompile/executeRename/executeReload 的字段名与实际 Command 类不匹配 → 缓解：Task 2 重写这些方法，直接使用 Map 参数
- GraphCommand 依赖 JADX 内部的 graph 生成能力，需确认 API 是否暴露 → 缓解：检查 API，未暴露则用 usage 递归模拟
- 缓存层可能返回过期数据 → 缓解：设置 TTL + reload 时清除缓存

**Autonomy Level:** Full

---

### Task 1: 创建 CommentCommand — 代码注释增删改查

**Depends on:** None
**Files:**
- Create: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/CommentCommand.java`
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/JadxAICLI.java`

- [ ] **Step 1: 检查 JADX API 是否暴露注释系统**

检查 `jadx.api.JadxDecompiler` 和 `jadx.api.JavaClass` 中是否有注释相关方法。

- [ ] **Step 2: 创建 CommentCommand**

实现注释的增删改查操作。jadx-gui 的注释系统基于 `ICodeAnnotation` 和 code metadata。CLI 版本通过 `JavaClass.getCodeInfo().getCodeMetadata()` 访问注释，如果 API 不支持写入则只实现读取。

支持的子操作：
- `list` — 列出某个类的所有注释
- `get` — 获取指定位置的注释
- `add` — 在指定位置添加注释（如果 API 支持）
- `remove` — 删除指定位置的注释

- [ ] **Step 3: 注册到 JadxAICLI**

在 JadxAICLI 的 @Command subcommands 中添加 CommentCommand.class

- [ ] **Step 4: 注册到 DaemonServer.buildRegistry()**

添加 `reg.register("comment", args -> executeComment(args));`

- [ ] **Step 5: 提交**
Run: `git add jadx-ai-cli/ && git commit -m "feat(jadx-ai-cli): add comment command for code annotations"`

---

### Task 2: 修复 DaemonServer 已知 bug — 字段名映射错误 + 补全命令注册

**Depends on:** None
**Files:**
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/daemon/DaemonServer.java`

- [ ] **Step 1: 修复 executeDecompile — 使用 Map 参数直接取值**

当前 `executeDecompile` 引用了 `cmd.showLineNumbers`、`cmd.format` 等不存在的字段。改为直接从 `args` Map 中取值：

```java
private Object executeDecompile(Map<String, Object> args) throws Exception {
    String className = (String) args.get("class");
    String methodName = (String) args.get("method");
    boolean withSmali = Boolean.TRUE.equals(args.get("withSmali"));
    boolean lineMap = Boolean.TRUE.equals(args.get("lineMap"));

    JavaClass cls = decompiler.searchJavaClassByOrigFullName(className);
    if (cls == null) {
        return JsonOutput.error("ClassNotFound", "Class not found: " + className);
    }
    if (methodName != null) {
        for (JavaMethod m : cls.getMethods()) {
            if (m.getName().equals(methodName)) {
                Map<String, Object> result = new HashMap<>();
                result.put("class", cls.getFullName());
                result.put("method", m.getName());
                result.put("code", m.getCodeStr());
                if (withSmali) result.put("smali", cls.getSmali());
                return result;
            }
        }
        return JsonOutput.error("MethodNotFound", "Method not found: " + methodName);
    }
    Map<String, Object> result = new HashMap<>();
    result.put("class", cls.getFullName());
    result.put("code", cls.getCode().toString());
    if (withSmali) result.put("smali", cls.getSmali());
    if (lineMap) result.put("lineMap", buildLineMap(cls));
    return result;
}
```

- [ ] **Step 2: 修复 executeRename — 使用 Map 参数直接取值**

同样改为直接从 args 取值，不引用 RenameCommand 字段。

- [ ] **Step 3: 修复 executeReload — 使用 Map 参数直接取值**

同样改为直接从 args 取值。

- [ ] **Step 4: 补全 daemon 命令注册**

在 `buildRegistry()` 中添加缺失的命令：
```java
reg.register("export", args -> executeExport(args));
reg.register("resources", args -> executeResources(args));
reg.register("line-map", args -> executeLineMap(args));
reg.register("package-detail", args -> executePackageDetail(args));
```

并实现对应的 `executeExport`、`executeResources`、`executeLineMap`、`executePackageDetail` 方法。

- [ ] **Step 5: 提交**
Run: `git add jadx-ai-cli/src/main/java/jadx/ai/cli/daemon/DaemonServer.java && git commit -m "fix(jadx-ai-cli): fix daemon field mapping bugs and add missing command registrations"`

---

### Task 3: 创建 GraphCommand — 调用图/继承图/控制流图

**Depends on:** None
**Files:**
- Create: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/GraphCommand.java`
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/JadxAICLI.java`

- [ ] **Step 1: 检查 JADX graph API**

检查 `jadx.api` 中是否暴露了 graph 生成能力。jadx-gui 使用的是内部 `jadx.core.dex.visitors.debuginfo` 和自定义 graph 渲染。如果 API 未暴露，则用 UsageCommand 的递归引用分析来模拟调用图和继承图。

- [ ] **Step 2: 创建 GraphCommand**

支持三种图类型：
- `call-graph` — 方法调用图（基于 usage 递归分析）
- `inheritance` — 类继承图（基于 getDeclaringClass/getTopParentClass/getInnerClasses）
- `cfg` — 控制流图（如果 API 暴露；否则标记为 unsupported）

输出格式：JSON 的节点-边结构（nodes + edges），方便下游工具渲染为 Mermaid/DOT。

- [ ] **Step 3: 注册到 JadxAICLI 和 DaemonServer**

- [ ] **Step 4: 提交**
Run: `git add jadx-ai-cli/ && git commit -m "feat(jadx-ai-cli): add graph command for call/inheritance graph generation"`

---

### Task 4: 创建 HookCommand — Frida/Xposed Hook 片段生成

**Depends on:** None
**Files:**
- Create: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/HookCommand.java`
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/JadxAICLI.java`

- [ ] **Step 1: 分析 jadx-gui 的 Frida/Xposed 片段生成逻辑**

读取 jadx-gui 中 FridaAction 和 XposedAction 的源码，了解片段生成的具体逻辑和模板。

- [ ] **Step 2: 创建 HookCommand**

支持两种输出：
- `frida` — 生成 Frida hook 脚本（Interceptor.attach 模式）
- `xposed` — 生成 Xposed 模块代码（handleLoadPackage + XC_MethodHook）

参数：
- `--class` — 目标类
- `--method` — 目标方法（可选，不指定则 hook 整个类）
- `--type` — frida 或 xposed
- `--lang` — xposed 时选择 java 或 kotlin

- [ ] **Step 3: 注册到 JadxAICLI 和 DaemonServer**

- [ ] **Step 4: 提交**
Run: `git add jadx-ai-cli/ && git commit -m "feat(jadx-ai-cli): add hook command for Frida/Xposed snippet generation"`

---

### Task 5: 创建 NavigateCommand — APK 入口点导航

**Depends on:** None
**Files:**
- Create: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/NavigateCommand.java`
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/JadxAICLI.java`

- [ ] **Step 1: 分析 jadx-gui 入口点识别逻辑**

jadx-gui 通过 NavigationMenu 的 "Go to Main Activity" 和 "Go to Application class" 来定位入口。需要分析它是如何识别这些入口的（解析 AndroidManifest.xml）。

- [ ] **Step 2: 创建 NavigateCommand**

支持：
- `main-activity` — 从 AndroidManifest.xml 提取主 Activity
- `application` — 提取 Application 类
- `manifest` — 提取完整 AndroidManifest.xml 关键信息
- `entry-points` — 综合列出所有入口点（Activity/Service/Receiver/Provider）

- [ ] **Step 3: 注册到 JadxAICLI 和 DaemonServer**

- [ ] **Step 4: 提交**
Run: `git add jadx-ai-cli/ && git commit -m "feat(jadx-ai-cli): add navigate command for APK entry point discovery"`

---

### Task 6: 添加 Daemon 结果缓存 — 连续调用性能优化

**Depends on:** Task 2
**Files:**
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/daemon/DaemonServer.java`
- Create: `jadx-ai-cli/src/main/java/jadx/ai/cli/daemon/DaemonCache.java`

- [ ] **Step 1: 创建 DaemonCache — 基于 TTL 的 LRU 缓存**

```java
package jadx.ai.cli.daemon;

import java.util.LinkedHashMap;
import java.util.Map;

public class DaemonCache {
    private final long ttlMs;
    private final int maxSize;
    private final Map<String, CacheEntry> cache;

    public DaemonCache(long ttlMs, int maxSize) {
        this.ttlMs = ttlMs;
        this.maxSize = maxSize;
        this.cache = new LinkedHashMap<>(maxSize, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, CacheEntry> eldest) {
                return size() > maxSize;
            }
        };
    }

    public Object get(String key) {
        CacheEntry entry = cache.get(key);
        if (entry == null || System.currentTimeMillis() - entry.timestamp > ttlMs) {
            cache.remove(key);
            return null;
        }
        return entry.value;
    }

    public void put(String key, Object value) {
        cache.put(key, new CacheEntry(value, System.currentTimeMillis()));
    }

    public void invalidate(String key) {
        cache.remove(key);
    }

    public void invalidateAll() {
        cache.clear();
    }

    public int size() {
        return cache.size();
    }

    private static class CacheEntry {
        final Object value;
        final long timestamp;
        CacheEntry(Object value, long timestamp) {
            this.value = value;
            this.timestamp = timestamp;
        }
    }
}
```

- [ ] **Step 2: 集成缓存到 DaemonServer**

1. 在 DaemonServer 中添加 DaemonCache 字段
2. 在 dispatch() 方法中，对查询类命令先查缓存
3. 缓存 key 格式：`command:argsHash`
4. 默认 TTL：5 分钟，默认最大容量：500
5. reload/shutdown 命令触发 invalidateAll()

- [ ] **Step 3: 注册缓存相关 daemon 命令**

添加 `cache-stats`（缓存统计）和 `cache-clear`（清空缓存）到 registry。

- [ ] **Step 4: 提交**
Run: `git add jadx-ai-cli/ && git commit -m "feat(jadx-ai-cli): add daemon result cache for repeated query performance"`
