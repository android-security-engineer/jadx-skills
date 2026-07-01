package jadx.ai.cli.server;

import java.util.HashMap;
import java.util.Map;

/**
 * Result of a command execution in the server.
 */
public class CommandResult {

	private final boolean success;
	private final Object data;
	private final String error;
	private final long durationMs;
	private final boolean cached;

	private CommandResult(boolean success, Object data, String error, long durationMs, boolean cached) {
		this.success = success;
		this.data = data;
		this.error = error;
		this.durationMs = durationMs;
		this.cached = cached;
	}

	public static CommandResult success(Object data, long durationMs) {
		return new CommandResult(true, data, null, durationMs, false);
	}

	public static CommandResult cached(Object data, long durationMs) {
		return new CommandResult(true, data, null, durationMs, true);
	}

	public static CommandResult error(Exception e, long durationMs) {
		return new CommandResult(false, null, e.getMessage() != null ? e.getMessage() : e.getClass().getName(), durationMs, false);
	}

	public static CommandResult error(String message, long durationMs) {
		return new CommandResult(false, null, message, durationMs, false);
	}

	public boolean isSuccess() {
		return success;
	}

	public Object getData() {
		return data;
	}

	public String getError() {
		return error;
	}

	public long getDurationMs() {
		return durationMs;
	}

	public boolean isCached() {
		return cached;
	}

	public Map<String, Object> toMap() {
		Map<String, Object> map = new HashMap<>();
		map.put("success", success);
		if (success) {
			map.put("data", data);
			map.put("cached", cached);
		} else {
			map.put("error", error);
		}
		map.put("durationMs", durationMs);
		return map;
	}
}
