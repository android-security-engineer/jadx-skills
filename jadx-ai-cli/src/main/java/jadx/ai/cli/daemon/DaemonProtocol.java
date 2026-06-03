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
