package jadx.ai.cli.commands;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import jadx.ai.cli.daemon.DaemonClient;
import jadx.ai.cli.daemon.DaemonProtocol;
import jadx.ai.cli.output.JsonOutput;
import jadx.ai.cli.server.ServerCore;
import jadx.api.JadxArgs;
import jadx.api.JadxDecompiler;

/**
 * Manage the unified JADX analysis server with multi-APK support.
 *
 * Usage:
 *   jadx-ai server start app1.apk              # Start server, load app1.apk
 *   jadx-ai server start app2.apk --port 17531 # Start on different port, load app2.apk
 *   jadx-ai server stop                         # Stop server
 *   jadx-ai server status                       # Check server status
 *   jadx-ai server session-open /path/to/apk    # Load additional APK into running server
 *   jadx-ai server session-list                 # List all loaded APKs
 *   jadx-ai server session-close <sessionId>    # Unload an APK
 */
@Command(name = "server", description = "Manage the JADX analysis server (multi-APK, persistent)")
public class ServerCommand extends AbstractCommand {

	@Parameters(index = "0", description = "Action: start, stop, status, session-open, session-list, session-close",
			defaultValue = "status")
	protected String action;

	@Option(names = {"-p", "--port"}, description = "Server TCP port", defaultValue = "17530")
	protected int port;

	@Option(names = {"--background"}, description = "Run server in background (fork process)")
	protected boolean background;

	// --deobfuscation is inherited from AbstractCommand.

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		DaemonClient client = new DaemonClient();
		switch (action.toLowerCase()) {
			case "start":
				return handleStart(client);
			case "stop":
				return handleStop(client);
			case "status":
				return handleStatus(client);
			case "session-open":
				return handleSessionOpen(client);
			case "session-list":
				return handleSessionList(client);
			case "session-close":
				return handleSessionClose(client);
			default:
				return JsonOutput.error("InvalidAction",
						"Unknown action: " + action + ". Use: start, stop, status, session-open, session-list, session-close");
		}
	}

	private Object handleStart(DaemonClient client) throws Exception {
		if (client.isDaemonRunning(port)) {
			// Server already running — if an inputFile was provided, open a new session
			if (inputFile != null) {
				return handleSessionOpen(client);
			}
			return JsonOutput.error("ServerAlreadyRunning",
					"Server is already running on port " + port + ". Use 'session-open' to load additional APKs.");
		}

		if (inputFile == null) {
			return JsonOutput.error("MissingInput",
					"Input file required for server start. Usage: jadx-ai server start <apk>");
		}

		if (background) {
			String javaHome = System.getProperty("java.home");
			String javaBin = javaHome + File.separator + "bin" + File.separator + "java";
			String classpath = System.getProperty("java.class.path");

			ProcessBuilder pb = new ProcessBuilder(javaBin, "-cp", classpath,
					"-Djadx.server.port=" + port,
					"-Djadx.server.input=" + inputFile.getAbsolutePath(),
					"jadx.ai.cli.server.JadxServer");
			pb.redirectErrorStream(true);
			pb.start();

			// Wait for server to be ready
			for (int i = 0; i < 20; i++) {
				Thread.sleep(500);
				if (client.isDaemonRunning(port)) {
					return JsonOutput.ok("Server started on port " + port + " with " + inputFile.getName() + " loaded");
				}
			}
			return JsonOutput.error("ServerStartFailed", "Server failed to start within 10 seconds");
		}

		return JsonOutput.ok("Use --background to start server in background. Foreground: run JadxServer directly.");
	}

	private Object handleStop(DaemonClient client) {
		if (!client.isDaemonRunning(port)) {
			return JsonOutput.ok("Server is not running");
		}
		DaemonProtocol.Response resp = client.shutdown(port);
		if (resp.success) {
			return JsonOutput.ok("Server stopped");
		}
		return JsonOutput.error("ShutdownFailed", resp.error);
	}

	private Object handleStatus(DaemonClient client) {
		if (!client.isDaemonRunning(port)) {
			return JsonOutput.ok(Map.of("status", "not running", "port", port));
		}

		// Query server status via TCP
		try {
			Map<String, Object> args = new HashMap<>();
			DaemonProtocol.Response resp = client.sendCommand("status", args, port);
			if (resp.success) {
				return resp.data;
			}
		} catch (Exception ignored) {
		}

		DaemonProtocol.StatusResponse status = client.status(port);
		if (status == null) {
			return JsonOutput.ok(Map.of("status", "running", "port", port));
		}
		return JsonOutput.ok(status);
	}

	private Object handleSessionOpen(DaemonClient client) throws Exception {
		if (inputFile == null) {
			return JsonOutput.error("MissingInput", "Input file required. Usage: jadx-ai server session-open <apk>");
		}
		if (!client.isDaemonRunning(port)) {
			// Start server first, then load
			return handleStart(client);
		}

		Map<String, Object> args = new HashMap<>();
		args.put("inputPath", inputFile.getAbsolutePath());
		args.put("deobfuscation", deobfuscation);

		DaemonProtocol.Response resp = client.sendCommand("session-open", args, port);
		if (resp.success) {
			return resp.data;
		}
		return JsonOutput.error("SessionOpenFailed", resp.error);
	}

	private Object handleSessionList(DaemonClient client) throws Exception {
		if (!client.isDaemonRunning(port)) {
			return JsonOutput.ok("Server is not running");
		}
		DaemonProtocol.Response resp = client.sendCommand("session-list", null, port);
		if (resp.success) {
			return resp.data;
		}
		return JsonOutput.error("SessionListFailed", resp.error);
	}

	private Object handleSessionClose(DaemonClient client) throws Exception {
		if (!client.isDaemonRunning(port)) {
			return JsonOutput.ok("Server is not running");
		}
		// Need sessionId — for now use input path to resolve
		Map<String, Object> args = new HashMap<>();
		if (inputFile != null) {
			args.put("inputPath", inputFile.getAbsolutePath());
		}
		DaemonProtocol.Response resp = client.sendCommand("session-close", args, port);
		if (resp.success) {
			return resp.data;
		}
		return JsonOutput.error("SessionCloseFailed", resp.error);
	}

	@Override
	protected boolean isDaemonCommand() {
		return true;
	}
}
