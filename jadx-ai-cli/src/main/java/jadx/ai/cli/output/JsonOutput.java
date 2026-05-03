package jadx.ai.cli.output;

import java.util.List;

public class JsonOutput {
	private boolean success;
	private String errorType;
	private String errorMessage;
	private Object data;

	private JsonOutput() {
	}

	public static JsonOutput ok(Object data) {
		JsonOutput out = new JsonOutput();
		out.success = true;
		out.data = data;
		return out;
	}

	public static JsonOutput error(String type, String message) {
		JsonOutput out = new JsonOutput();
		out.success = false;
		out.errorType = type;
		out.errorMessage = message;
		return out;
	}

	public static JsonOutput list(List<?> items) {
		JsonOutput out = new JsonOutput();
		out.success = true;
		out.data = items;
		return out;
	}

	public boolean isSuccess() {
		return success;
	}

	public String getErrorType() {
		return errorType;
	}

	public String getErrorMessage() {
		return errorMessage;
	}

	public Object getData() {
		return data;
	}
}
