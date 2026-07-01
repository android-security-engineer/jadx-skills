package jadx.ai.cli.commands;

import java.io.File;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import jadx.ai.cli.daemon.DaemonClient;
import jadx.ai.cli.daemon.DaemonProtocol;
import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;

@Command(name = "daemon", description = "Manage the JADX AI daemon for index reuse")
public class DaemonCommand extends AbstractCommand {

	@Parameters(index = "0", description = "Action: start, stop, status", defaultValue = "status")
	protected String action;

	@Option(names = { "-p", "--port" }, description = "Daemon port", defaultValue = "17530")
	protected int port;

	@Option(names = { "--background" }, description = "Run daemon in background (fork a new process)")
	protected boolean background;

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
			default:
				return JsonOutput.error("InvalidAction",
						"Unknown action: " + action + ". Use: start, stop, status");
		}
	}

	private Object handleStart(DaemonClient client) throws Exception {
		if (client.isDaemonRunning(port)) {
			return JsonOutput.error("DaemonAlreadyRunning",
					"Daemon is already running on port " + port);
		}
		if (background) {
			String javaHome = System.getProperty("java.home");
			String javaBin = javaHome + File.separator + "bin" + File.separator + "java";
			String classpath = System.getProperty("java.class.path");
			ProcessBuilder pb = new ProcessBuilder(javaBin, "-cp", classpath,
					"-Djadx.daemon.port=" + port,
					"-Djadx.daemon.input=" + inputFile.getAbsolutePath(),
					"jadx.ai.cli.daemon.DaemonServer");
			pb.redirectErrorStream(true);
			pb.start();
			for (int i = 0; i < 10; i++) {
				Thread.sleep(500);
				if (client.isDaemonRunning(port)) {
					DaemonProtocol.StatusResponse status = client.status(port);
					return JsonOutput.ok("Daemon started: " + status.classCount + " classes loaded on port " + port);
				}
			}
			return JsonOutput.error("DaemonStartFailed", "Daemon failed to start within 5 seconds");
		}
		return JsonOutput.ok("Use --background to start daemon in background. Foreground mode: run DaemonServer directly.");
	}

	private Object handleStop(DaemonClient client) {
		if (!client.isDaemonRunning(port)) {
			return JsonOutput.ok("Daemon is not running");
		}
		DaemonProtocol.Response resp = client.shutdown(port);
		if (resp.success) {
			return JsonOutput.ok("Daemon stopped");
		}
		return JsonOutput.error("ShutdownFailed", resp.error);
	}

	private Object handleStatus(DaemonClient client) {
		DaemonProtocol.StatusResponse status = client.status(port);
		if (status == null) {
			return JsonOutput.ok("Daemon is not running");
		}
		return JsonOutput.ok(status);
	}
}
