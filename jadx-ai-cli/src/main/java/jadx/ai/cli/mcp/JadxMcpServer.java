package jadx.ai.cli.mcp;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import jadx.api.JadxDecompiler;

/**
 * MCP server entry point implementing JSON-RPC 2.0 over stdio.
 * Reads requests from System.in, writes responses to System.out.
 */
public class JadxMcpServer {

	private final JadxDecompiler decompiler;
	private final McpCommandDispatcher dispatcher;
	private final Gson gson = new GsonBuilder().disableHtmlEscaping().create();

	public JadxMcpServer(JadxDecompiler decompiler) {
		this.decompiler = decompiler;
		this.dispatcher = new McpCommandDispatcher(decompiler);
	}

	public void run() {
		try (BufferedReader reader = new BufferedReader(new InputStreamReader(System.in))) {
			String line;
			while ((line = reader.readLine()) != null) {
				if (line.trim().isEmpty()) {
					continue;
				}
				try {
					Map<String, Object> request = gson.fromJson(line, Map.class);
					Object id = request.get("id");
					String method = (String) request.get("method");
					Map<String, Object> params = (Map<String, Object>) request.get("params");

					Object result = handleMethod(method, params);
					writeResponse(id, result);
				} catch (Exception e) {
					writeError(null, -32600, "Invalid request: " + e.getMessage());
				}
			}
		} catch (Exception e) {
			System.err.println("MCP server error: " + e.getMessage());
		}
	}

	private Object handleMethod(String method, Map<String, Object> params) throws Exception {
		switch (method) {
			case "initialize":
				return buildInitializeResult();
			case "tools/list":
				return buildToolsListResult();
			case "tools/call":
				return handleToolCall(params);
			case "ping":
				return "pong";
			default:
				throw new IllegalArgumentException("Unknown method: " + method);
		}
	}

	private Object buildInitializeResult() {
		Map<String, Object> result = new LinkedHashMap<>();
		Map<String, Object> capabilities = new LinkedHashMap<>();
		Map<String, Object> tools = new LinkedHashMap<>();
		tools.put("listChanged", false);
		capabilities.put("tools", tools);
		result.put("capabilities", capabilities);

		Map<String, Object> serverInfo = new LinkedHashMap<>();
		serverInfo.put("name", "jadx-mcp-server");
		serverInfo.put("version", "1.0.0");
		result.put("serverInfo", serverInfo);

		return result;
	}

	private Object buildToolsListResult() {
		Map<String, Object> result = new LinkedHashMap<>();
		result.put("tools", McpToolDefinitions.getAll());
		return result;
	}

	private Object handleToolCall(Map<String, Object> params) throws Exception {
		String toolName = (String) params.get("name");
		Map<String, Object> arguments = (Map<String, Object>) params.get("arguments");
		if (arguments == null) {
			arguments = new HashMap<>();
		}

		Object toolResult = dispatcher.dispatch(toolName, arguments);

		Map<String, Object> result = new LinkedHashMap<>();
		List<Map<String, Object>> content = new java.util.ArrayList<>();

		Map<String, Object> textContent = new LinkedHashMap<>();
		textContent.put("type", "text");
		textContent.put("text", gson.toJson(toolResult));
		content.add(textContent);

		result.put("content", content);
		return result;
	}

	private void writeResponse(Object id, Object result) {
		Map<String, Object> response = new LinkedHashMap<>();
		response.put("jsonrpc", "2.0");
		response.put("id", id);
		response.put("result", result);
		System.out.println(gson.toJson(response));
		System.out.flush();
	}

	private void writeError(Object id, int code, String message) {
		Map<String, Object> response = new LinkedHashMap<>();
		response.put("jsonrpc", "2.0");
		response.put("id", id);

		Map<String, Object> error = new LinkedHashMap<>();
		error.put("code", code);
		error.put("message", message);
		response.put("error", error);

		System.out.println(gson.toJson(response));
		System.out.flush();
	}
}