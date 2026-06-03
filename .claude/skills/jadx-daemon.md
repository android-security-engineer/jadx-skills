---
name: jadx-daemon
description: Manage the JADX AI daemon for persistent index reuse across CLI commands. Starts a background process that holds JadxDecompiler in memory for fast repeated queries.
---

# JADX Daemon Skill

Start a background daemon that holds the JADX decompiler in memory, enabling fast repeated queries without reloading the APK each time.

## When to Use

When performing multiple queries on the same APK, or when query speed matters. The daemon eliminates the 5-15 second `load()` phase on every command.

## Commands

### Start daemon

```bash
jadx-ai daemon start app.apk --background
```

Forks a background JVM process that loads the APK and builds all indexes. Waits up to 5 seconds for confirmation.

### Check status

```bash
jadx-ai daemon status
```

Returns: classCount, methodCount, uptimeMs, memoryUsedMB, inputFile path.

### Stop daemon

```bash
jadx-ai daemon stop
```

Sends shutdown command. Daemon cleans up PID file and closes decompiler.

## Automatic Detection

When any CLI command runs (search, usage, list, etc.), AbstractCommand automatically:
1. Checks PID file at `/tmp/jadx-ai-daemon-17530.pid`
2. If daemon is reachable, forwards the command via JSON-over-Socket
3. If daemon is unavailable, falls back to normal local mode

No manual configuration needed — daemon mode is transparent.

## Architecture

- **Daemon** holds JadxDecompiler instance in memory, listens on localhost:17530
- **Client** (each CLI command) connects via TCP, sends one-line JSON request
- **Protocol**: `JADX-AI-DAEMON` magic header + command name + args map
- **Fallback**: If daemon fails, automatically degrades to one-shot local mode

## Performance

| Mode | First command | Subsequent commands |
|------|-------------|-------------------|
| Local (no daemon) | 5-15s (load) + query | 5-15s (load) + query |
| Daemon | 5-15s (daemon startup) | <100ms (query only) |

## Port Configuration

Default port: 17530. Configure via `--port` flag:

```bash
jadx-ai daemon start app.apk --background --port 17531
```

Multiple daemons can run simultaneously on different ports for different APKs.