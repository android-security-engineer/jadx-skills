package jadx.ai.cli.server;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import jadx.api.JadxArgs;
import jadx.ai.cli.daemon.DaemonProtocol;

/**
 * Main entry point for the JADX server (multi-APK mode).
 *
 * Starts the ServerCore, loads an initial APK (if provided),
 * and listens for TCP connections using the same DaemonProtocol.
 *
 * The key difference from the old DaemonServer:
 * - Supports multiple APKs via SessionManager
 * - Project persistence via ProjectManager
 * - All commands are session-scoped
 */
public class JadxServer {

	private static final int MAX_THREADS = 10;
	private final ServerCore core;
	private final int port;
	private final Gson gson = new GsonBuilder().disableHtmlEscaping().create();
	private volatile boolean running = true;
	private ServerSocket serverSocket;
	private final ExecutorService executor = Executors.newFixedThreadPool(MAX_THREADS);

	public JadxServer(int port) {
		this.port = port;
		this.core = new ServerCore();
	}

	public void start(String initialInputPath) throws Exception {
		core.start();

		// Load initial APK if provided
		if (initialInputPath != null) {
			java.io.File inputFile = new java.io.File(initialInputPath);
			if (inputFile.exists()) {
				JadxArgs args = new JadxArgs();
				args.setInputFile(inputFile);
				args.setSkipResources(false);
				core.loadApk(initialInputPath, args);
				System.out.println("Loaded initial APK: " + initialInputPath
						+ " (" + core.getSessionManager().getSessionCount() + " session(s))");
			}
		}

		// Write PID file
		core.writePidFile(port);

		// Register shutdown hook
		Runtime.getRuntime().addShutdownHook(new Thread(() -> {
			running = false;
			core.stop();
		}));

		// Start TCP listener
		serverSocket = new ServerSocket(port);
		System.out.println("JADX Server started on port " + port
				+ " (multi-APK mode, " + MAX_THREADS + " worker threads)");

		while (running) {
			try {
				Socket client = serverSocket.accept();
				executor.submit(() -> handleClient(client));
			} catch (java.net.SocketException e) {
				if (running) throw e;
				break;
			}
		}
	}

	private void handleClient(Socket client) {
		try (BufferedReader in = new BufferedReader(new InputStreamReader(client.getInputStream()));
				OutputStream out = client.getOutputStream()) {
			String line = in.readLine();
			if (line == null) return;

			DaemonProtocol.Request request = gson.fromJson(line, DaemonProtocol.Request.class);
			if (!DaemonProtocol.MAGIC.equals(request.magic)) {
				sendError(out, "Invalid magic header");
				return;
			}

			DaemonProtocol.Response response = dispatch(request);
			String json = gson.toJson(response);
			out.write((json + "\n").getBytes("UTF-8"));
			out.flush();
		} catch (Exception e) {
			System.err.println("Error handling client: " + e.getMessage());
		} finally {
			try { client.close(); } catch (IOException ignored) {}
		}
	}

	private DaemonProtocol.Response dispatch(DaemonProtocol.Request request) {
		long start = System.currentTimeMillis();
		DaemonProtocol.Response response = new DaemonProtocol.Response();

		// System commands handled directly
		if ("shutdown".equals(request.command)) {
			response.success = true;
			response.data = "shutting down";
			new Thread(() -> {
				try { Thread.sleep(100); stop(); } catch (Exception ignored) {}
			}).start();
			return response;
		}

		// All other commands go through ServerCore
		CommandResult result = core.executeCommand(request.command, request.args);
		response.success = result.isSuccess();
		if (result.isSuccess()) {
			response.data = result.getData();
		} else {
			response.error = result.getError();
		}
		response.latencyMs = System.currentTimeMillis() - start;
		return response;
	}

	private void sendError(OutputStream out, String message) throws IOException {
		DaemonProtocol.Response resp = new DaemonProtocol.Response();
		resp.success = false;
		resp.error = message;
		out.write((gson.toJson(resp) + "\n").getBytes("UTF-8"));
		out.flush();
	}

	public void stop() {
		running = false;
		try { if (serverSocket != null) serverSocket.close(); } catch (IOException ignored) {}
		core.stop();
		executor.shutdownNow();
	}

	public static void main(String[] args) throws Exception {
		String portStr = System.getProperty("jadx.server.port", String.valueOf(DaemonProtocol.DEFAULT_PORT));
		String inputPath = System.getProperty("jadx.server.input");
		if (inputPath == null && args.length > 0) {
			inputPath = args[0];
		}

		int port = Integer.parseInt(portStr);
		JadxServer server = new JadxServer(port);
		server.start(inputPath);
	}
}
