# CLI Daemon Mode — 让 JADX AI CLI 复用索引加速查询

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** 为 jadx-ai-cli 增加 daemon 模式，后台常驻进程持有 JadxDecompiler 实例，CLI 命令通过 localhost TCP 连接 daemon 复用已加载索引，避免每次命令重新 load() APK。

**Architecture:** 用户启动 `jadx-ai daemon start app.apk --background` → 后台进程加载 APK 建索引 → 监听 localhost:17530 → 后续命令（search/usage/list 等）自动检测 daemon → 通过 JSON-over-Socket 协议转发请求 → daemon 内部直接调用 JadxDecompiler API → 返回结果 → 跳过 load() 阶段。若 daemon 不可用则自动降级为当前的一次性模式。

**Tech Stack:** Java 11+, Java Socket (ServerSocket/Socket), Gson 2.10.1, picocli 4.7.5, jadx-core (现有依赖)

**Scope:** Medium

**Risk:** Medium — 修改 AbstractCommand 核心生命周期，影响所有命令；但降级机制确保无 daemon 时行为不变

**Risks:**
- Task 5 修改 AbstractCommand.run() 核心流程 → 缓解：daemon 不可用时自动降级为原流程，零破坏性
- Task 2 的 Socket 协议需处理并发 → 缓解：单线程顺序处理请求，简单可靠
- 守护进程僵死 → 缓解：PID 文件 + 连接超时 + 自动降级

**Autonomy Level:** Full

---

### Task 1: 创建 Daemon 通信协议

**Depends on:** None
**Files:**
- Create: `jadx-ai-cli/src/main/java/jadx/ai/cli/daemon/DaemonProtocol.java`

- [ ] **Step 1: 创建 DaemonProtocol 类**

```java
package jadx.ai.cli.daemon;

import java.util.Map;

public class DaemonProtocol {

	public static final int DEFAULT_PORT = 17530;
	public static final String HOST = "127.0.0.1";
	public static final String PROTOCOL_VERSION = "1.0";
	public static final String MAGIC = "JADX-AI-DAEMON";

	public static class Request {
		public String magic = MAGIC;
		public String version = PROTOCOL_VERSION;
		public String command;
		public Map<String, Object> args;
	}

	public static class Response {
		public boolean success;
		public Object data;
		public String error;
		public long latencyMs;
	}

	public static class CommandRequest extends Request {
		public CommandRequest(String cmd, Map<String, Object> args) {
			this.command = cmd;
			this.args = args;
		}
	}

	public static class StatusResponse {
		public String status;
		public String inputFile;
		public int classCount;
		public int methodCount;
		public long uptimeMs;
		public long memoryUsedMB;
	}
}
```

- [ ] **Step 2: 提交**
Run: `git add jadx-ai-cli/src/main/java/jadx/ai/cli/daemon/DaemonProtocol.java && git commit -m "feat(jadx-ai-cli): add daemon protocol definition for CLI index reuse"`

---

### Task 2: 创建 DaemonServer

**Depends on:** Task 1
**Files:**
- Create: `jadx-ai-cli/src/main/java/jadx/ai/cli/daemon/DaemonServer.java`

- [ ] **Step 1: 创建 DaemonServer 类 — 加载 APK、监听请求、路由到各命令**

完整代码见 Plan 文件附件。关键要点：
- 构造函数接收 JadxArgs + port
- `start()` 方法：创建 JadxDecompiler → load() → 写 PID → accept loop
- `handleClient()`：读一行 JSON → dispatch → 写一行 JSON 响应
- `dispatch()`：ping/shutdown/status 路由 + executeCommand 路由
- `executeCommand()`：按 command 名创建对应 Command 子类 → 设置参数 → execute(decompiler)
- `buildStatus()`：返回 classCount、methodCount、uptimeMs、memoryUsedMB
- `stop()`：关闭 serverSocket + 关闭 decompiler + 删除 PID 文件
- `main()`：支持独立启动（从系统属性读取 input/port）

支持的命令路由：search, usage, list, info, class-detail, decompile, rename, reload

- [ ] **Step 2: 提交**
Run: `git add jadx-ai-cli/src/main/java/jadx/ai/cli/daemon/DaemonServer.java && git commit -m "feat(jadx-ai-cli): add daemon server that holds JadxDecompiler in memory"`

---

### Task 3: 创建 DaemonClient

**Depends on:** Task 1
**Files:**
- Create: `jadx-ai-cli/src/main/java/jadx/ai/cli/daemon/DaemonClient.java`

- [ ] **Step 1: 创建 DaemonClient 类 — 连接 daemon、发送请求、接收响应**

关键方法：
- `isDaemonRunning(port)` — 500ms 超时尝试连接
- `detectPort()` — 读 PID 文件获取端口号 + 验证 daemon 可用
- `sendCommand(command, args, port)` — 建立 Socket → 发送 JSON → 读响应 JSON
- `ping(port)` / `shutdown(port)` / `status(port)` — 快捷方法

超时参数：CONNECT_TIMEOUT_MS=500, READ_TIMEOUT_MS=30000

- [ ] **Step 2: 提交**
Run: `git add jadx-ai-cli/src/main/java/jadx/ai/cli/daemon/DaemonClient.java && git commit -m "feat(jadx-ai-cli): add daemon client for connecting to running daemon"`

---

### Task 4: 创建 DaemonCommand + 注册子命令

**Depends on:** Task 2, Task 3
**Files:**
- Create: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/DaemonCommand.java`
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/JadxAICLI.java`

- [ ] **Step 1: 创建 DaemonCommand — start/stop/status 子命令**

参数：action (start/stop/status), --port (默认17530), --background (fork 新 JVM 进程)

handleStart：检测是否已在运行 → 若 --background 则 ProcessBuilder fork DaemonServer → 等待最多 5 秒确认启动成功

handleStop：调用 client.shutdown(port)

handleStatus：调用 client.status(port) → 输出 JSON

- [ ] **Step 2: 在 JadxAICLI 中注册 DaemonCommand.class**

- [ ] **Step 3: 提交**
Run: `git add jadx-ai-cli/src/main/java/jadx/ai/cli/commands/DaemonCommand.java jadx-ai-cli/src/main/java/jadx/ai/cli/JadxAICLI.java && git commit -m "feat(jadx-ai-cli): add daemon CLI command for managing background index server"`

---

### Task 5: 修改 AbstractCommand — 自动 daemon 降级

**Depends on:** Task 3
**Files:**
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/AbstractCommand.java:168-266`
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/SearchCommand.java`（添加 buildDaemonArgs）
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/UsageCommand.java`（添加 buildDaemonArgs）

- [ ] **Step 1: 在 run() 方法开头插入 daemon 检测**

逻辑：
```
if (inputFile != null && !isDaemonCommand()) {
  DaemonClient client = new DaemonClient();
  int port = client.detectPort();
  if (port > 0) {
    Response resp = client.sendCommand(getDaemonCommandName(), buildDaemonArgs(), port);
    if (resp.success) { print resp.data; return; }
    // else: fall through to local mode
  }
}
// continue with original local mode (JadxDecompiler load/execute/close)
```

添加辅助方法：isDaemonCommand(), getDaemonCommandName(), buildDaemonArgs()

- [ ] **Step 2: SearchCommand 覆盖 buildDaemonArgs()**

映射所有搜索参数到 Map：type, query, limit, exact, searchParent, regex, ignoreCase, package, resourceType, maxSize

- [ ] **Step 3: UsageCommand 覆盖 buildDaemonArgs()**

映射：class, method, field, type, depth

- [ ] **Step 4: 提交**
Run: `git add jadx-ai-cli/src/main/java/jadx/ai/cli/commands/AbstractCommand.java jadx-ai-cli/src/main/java/jadx/ai/cli/commands/SearchCommand.java jadx-ai-cli/src/main/java/jadx/ai/cli/commands/UsageCommand.java && git commit -m "feat(jadx-ai-cli): auto-detect daemon in AbstractCommand, fall back to local mode"`

---

### Task 6: 创建 daemon skill 文档

**Depends on:** Task 4, Task 5
**Files:**
- Create: `.claude/skills/jadx-daemon.md`

- [ ] **Step 1: 创建 jadx-daemon skill 文档**

文档内容包括：
- daemon start/stop/status 命令用法
- 自动降级机制说明（daemon 不可用时自动走本地模式）
- 性能对比预期：本地模式每次 5-15 秒 load()；daemon 模式 <100ms 响应
- 端口配置（默认 17530）
- --background 启动方式说明

- [ ] **Step 2: 提交**
Run: `git add .claude/skills/jadx-daemon.md && git commit -m "docs(jadx-ai-cli): add daemon skill documentation"`