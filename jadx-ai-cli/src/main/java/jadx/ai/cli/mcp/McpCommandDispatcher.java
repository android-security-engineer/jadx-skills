package jadx.ai.cli.mcp;

import java.util.Map;

import jadx.ai.cli.commands.CommandDispatch;
import jadx.api.JadxDecompiler;

/**
 * Bridges MCP tool calls to the shared {@link CommandDispatch}. MCP tool names are
 * {@code jadx_<command>} with underscores; the corresponding CLI command name is the suffix with
 * {@code _} mapped to {@code -} (e.g. {@code jadx_class_detail} → {@code class-detail}). All
 * field-mapping lives in {@link CommandDispatch}, so this class is a thin name translator.
 */
public class McpCommandDispatcher {

	private static final String TOOL_PREFIX = "jadx_";

	private final JadxDecompiler decompiler;

	public McpCommandDispatcher(JadxDecompiler decompiler) {
		this.decompiler = decompiler;
	}

	public Object dispatch(String toolName, Map<String, Object> args) throws Exception {
		String command = toCommandName(toolName);
		if (command == null || !CommandDispatch.isKnown(command)) {
			throw new IllegalArgumentException("Unknown tool: " + toolName);
		}
		return CommandDispatch.run(command, args, decompiler);
	}

	/** {@code jadx_class_detail} → {@code class-detail}; returns null if not a jadx tool. */
	private static String toCommandName(String toolName) {
		if (toolName == null || !toolName.startsWith(TOOL_PREFIX)) {
			return null;
		}
		return toolName.substring(TOOL_PREFIX.length()).replace('_', '-');
	}
}
