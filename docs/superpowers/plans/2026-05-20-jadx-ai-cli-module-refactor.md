# Refactor: jadx-ai-cli 独立模块重构

**Goal:** 将 jadx-ai-cli 重构为完全独立可分发的 Gradle 模块，清理无用依赖，修复 API 边界违规，添加 shadow JAR 打包，为后续 CLI 能力扩充做好架构准备。

**Safety Net:** 现有 CommandsTest.java + 手动验证 build 成功

**Before/After:**
- Before: jadx-ai-cli 依赖未使用的 :jadx-cli，引用 jadx.core 内部类，无 fat JAR，daemon 命令路由硬编码
- After: jadx-ai-cli 仅依赖 :jadx-core，所有引用走 jadx.api 公共 API，shadow fat JAR 可独立运行，daemon 命令路由可扩展

**Scope:** Medium

**Risk:** Medium — 修改构建配置和核心代码，但行为不变

**Risks:**
- Task 2 移除 `:jadx-cli` 依赖可能导致编译失败（如果有运行时传递依赖） → 缓解：先检查所有 import，确认无 jadx.cli.* 引用
- Task 3 添加 shadow 插件可能改变 JAR 结构 → 缓解：shadow 是标准做法，jadx-cli 已在用
- Task 4 重构 daemon 路由可能影响现有 daemon 功能 → 缓解：保持 DaemonServer 的 executeCommand 行为不变，只改内部结构

**Autonomy Level:** Full

---

### Task 1: 清理无用依赖 — 移除 :jadx-cli 依赖

**Depends on:** None
**Files:**
- Modify: `jadx-ai-cli/build.gradle.kts:12`

- [ ] **Step 1: 验证 :jadx-cli 依赖确实未使用**

Run: `cd /data/local/tmp/workspace/github/AI-jadx && grep -r "jadx\.cli\." jadx-ai-cli/src/ --include="*.java" | grep -v "jadx\.ai\.cli" | head -20`

Expected: 无输出（确认无 jadx.cli.* import）

- [ ] **Step 2: 移除 build.gradle.kts 中的 :jadx-cli 依赖**

文件: `jadx-ai-cli/build.gradle.kts:12`

移除行: `implementation(project(":jadx-cli"))`

- [ ] **Step 3: 验证编译**
Run: `cd /data/local/tmp/workspace/github/AI-jadx && ./gradlew :jadx-ai-cli:compileJava --no-daemon 2>&1 | tail -5`

Expected: Exit code 0, output contains "BUILD SUCCESSFUL"

- [ ] **Step 4: 提交**
Run: `git add jadx-ai-cli/build.gradle.kts && git commit -m "refactor(jadx-ai-cli): remove unused :jadx-cli dependency"`

---

### Task 2: 修复 API 边界违规 — 消除 jadx.core 内部引用

**Depends on:** None
**Files:**
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/AbstractCommand.java:253`

- [ ] **Step 1: 查找所有 jadx.core 内部引用**

Run: `cd /data/local/tmp/workspace/github/AI-jadx && grep -rn "jadx\.core\." jadx-ai-cli/src/ --include="*.java" | grep -v "jadx\.core\.xmlgen" | head -20`

Expected: 找到 AbstractCommand.java 中的 ExportGradleType 引用

- [ ] **Step 2: 检查 ExportGradleType 是否在 jadx.api 中有等价物**

Run: `cd /data/local/tmp/workspace/github/AI-jadx && grep -rn "ExportGradleType" jadx-core/src/main/java/jadx/api/ --include="*.java" | head -5`

Expected: 如果在 jadx.api 中有，则改用 api 版本；如果没有，则保留但添加注释说明

- [ ] **Step 3: 修复引用**

如果 jadx.api 中有 ExportGradleType 的暴露：替换 import 路径
如果 jadx.api 中没有：保留当前引用，在 AbstractCommand 中添加注释 `// TODO: ExportGradleType should be exposed via jadx.api`

- [ ] **Step 4: 提交**
Run: `git add jadx-ai-cli/src/main/java/jadx/ai/cli/commands/AbstractCommand.java && git commit -m "refactor(jadx-ai-cli): fix jadx.core internal API reference"`

---

### Task 3: 添加 shadow JAR 打包 — 支持独立分发

**Depends on:** Task 1
**Files:**
- Modify: `jadx-ai-cli/build.gradle.kts`

- [ ] **Step 1: 添加 shadow 插件和配置**

在 `jadx-ai-cli/build.gradle.kts` 中：
1. 添加 shadow 插件: `id("com.gradleup.shadow")`
2. 配置 application 的 mainClass（已有）
3. 添加 shadowJar 任务配置（合并 service 文件等）

参考 jadx-cli/build.gradle.kts 的 shadow 配置模式。

- [ ] **Step 2: 验证 shadow JAR 构建**
Run: `cd /data/local/tmp/workspace/github/AI-jadx && ./gradlew :jadx-ai-cli:shadowJar --no-daemon 2>&1 | tail -5`

Expected: Exit code 0, output contains "BUILD SUCCESSFUL"

- [ ] **Step 3: 验证生成的 JAR 可运行**
Run: `cd /data/local/tmp/workspace/github/AI-jadx && java -jar jadx-ai-cli/build/libs/jadx-ai-cli-*.jar --help 2>&1 | head -5`

Expected: 输出包含 "jadx-ai" 和子命令列表

- [ ] **Step 4: 提交**
Run: `git add jadx-ai-cli/build.gradle.kts && git commit -m "build(jadx-ai-cli): add shadow plugin for fat JAR distribution"`

---

### Task 4: 重构 daemon 命令路由为可扩展注册机制

**Depends on:** None
**Files:**
- Create: `jadx-ai-cli/src/main/java/jadx/ai/cli/daemon/DaemonCommandRegistry.java`
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/daemon/DaemonServer.java`

- [ ] **Step 1: 创建 DaemonCommandRegistry — 可扩展的命令注册表**

```java
package jadx.ai.cli.daemon;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import jadx.api.JadxDecompiler;

public class DaemonCommandRegistry {

	private final Map<String, Function<Map<String, Object>, Object>> handlers = new HashMap<>();

	public void register(String commandName, Function<Map<String, Object>, Object> handler) {
		handlers.put(commandName, handler);
	}

	public boolean hasCommand(String commandName) {
		return handlers.containsKey(commandName);
	}

	public Object execute(String commandName, Map<String, Object> args) throws Exception {
		Function<Map<String, Object>, Object> handler = handlers.get(commandName);
		if (handler == null) {
			throw new IllegalArgumentException("Unknown command: " + commandName);
		}
		return handler.apply(args);
	}

	public static DaemonCommandRegistry createDefault(JadxDecompiler decompiler) {
		DaemonCommandRegistry registry = new DaemonCommandRegistry();
		// Commands will be registered by DaemonServer
		return registry;
	}
}
```

- [ ] **Step 2: 重构 DaemonServer 使用注册表**

修改 DaemonServer：
1. 添加 `DaemonCommandRegistry` 字段
2. 在构造函数或 `start()` 中注册所有命令处理器
3. `executeCommand()` 改为委托给 registry

- [ ] **Step 3: 提交**
Run: `git add jadx-ai-cli/src/main/java/jadx/ai/cli/daemon/DaemonCommandRegistry.java jadx-ai-cli/src/main/java/jadx/ai/cli/daemon/DaemonServer.java && git commit -m "refactor(jadx-ai-cli): extract daemon command routing to extensible registry"`

---

### Task 5: 添加 jadx-ai-cli 到 root 分发配置

**Depends on:** Task 3
**Files:**
- Modify: `build.gradle.kts`（root）

- [ ] **Step 1: 在 root build.gradle.kts 中添加 jadx-ai-cli 分发任务**

在 distribution 打包区域添加 jadx-ai-cli 的 shadow JAR 到分发目录。

- [ ] **Step 2: 验证**
Run: `cd /data/local/tmp/workspace/github/AI-jadx && ./gradlew :jadx-ai-cli:shadowJar --no-daemon 2>&1 | tail -3`

Expected: BUILD SUCCESSFUL

- [ ] **Step 3: 提交**
Run: `git add build.gradle.kts && git commit -m "build: add jadx-ai-cli to distribution packaging"`
