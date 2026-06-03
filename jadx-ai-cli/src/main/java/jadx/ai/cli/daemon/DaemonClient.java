package jadx.ai.cli.daemon;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class DaemonClient {

	private static final int CONNECT_TIMEOUT_MS = 500;
	private static final int READ_TIMEOUT_MS = 30000;
	private final Gson gson = new GsonBuilder().disableHtmlEscaping().create();

	public boolean isDaemonRunning(int port) {
		try (Socket socket = new Socket()) {
			socket.connect(new java.net.InetSocketAddress(DaemonProtocol.HOST, port), CONNECT_TIMEOUT_MS);
			return true;
		} catch (IOException e) {
			return false;
		}
	}

	public int detectPort() {
		Path defaultPid = Path.of(System.getProperty("java.io.tmpdir"),
				"jadx-ai-daemon-" + DaemonProtocol.DEFAULT_PORT + ".pid");
		if (Files.exists(defaultPid)) {
			try {
				String[] parts = Files.readString(defaultPid).trim().split("\n");
				int port = Integer.parseInt(parts[parts.length - 1].trim());
				if (isDaemonRunning(port)) {
					return port;
				}
			} catch (Exception ignored) {
			}
		}
		return -1;
	}

	public DaemonProtocol.Response sendCommand(String command, Map<String, Object> args, int port) {
		try (Socket socket = new Socket()) {
			socket.connect(new java.net.InetSocketAddress(DaemonProtocol.HOST, port), CONNECT_TIMEOUT_MS);
			socket.setSoTimeout(READ_TIMEOUT_MS);
			DaemonProtocol.CommandRequest request = new DaemonProtocol.CommandRequest(command, args);
			String json = gson.toJson(request);
			OutputStream out = socket.getOutputStream();
			out.write((json + "\n").getBytes("UTF-8"));
			out.flush();
			BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			String responseLine = in.readLine();
			if (responseLine == null) {
				DaemonProtocol.Response err = new DaemonProtocol.Response();
				err.success = false;
				err.error = "No response from daemon";
				return err;
			}
			return gson.fromJson(responseLine, DaemonProtocol.Response.class);
		} catch (IOException e) {
			DaemonProtocol.Response err = new DaemonProtocol.Response();
			err.success = false;
			err.error = "Cannot connect to daemon: " + e.getMessage();
			return err;
		}
	}

	public DaemonProtocol.Response ping(int port) {
		return sendCommand("ping", null, port);
	}

	public DaemonProtocol.Response shutdown(int port) {
		return sendCommand("shutdown", null, port);
	}

	public DaemonProtocol.StatusResponse status(int port) {
		DaemonProtocol.Response resp = sendCommand("status", null, port);
		if (resp.success && resp.data != null) {
			return gson.fromJson(gson.toJson(resp.data), DaemonProtocol.StatusResponse.class);
		}
		return null;
	}
}
