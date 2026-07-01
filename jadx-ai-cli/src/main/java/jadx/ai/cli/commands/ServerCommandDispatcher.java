package jadx.ai.cli.commands;

import java.util.Map;

import jadx.api.JadxDecompiler;
import jadx.ai.cli.server.AnalysisSession;
import jadx.ai.cli.server.SessionManager;

/**
 * Unified-server command dispatcher. A thin wrapper over {@link CommandDispatch}: it resolves the
 * session's decompiler and forwards execution, while keeping the server's notion of which commands
 * are read-only (for cache invalidation). All field-mapping lives in {@link CommandDispatch} so
 * there is no per-command duplication here.
 */
public class ServerCommandDispatcher {

	@SuppressWarnings("unused")
	private final SessionManager sessionManager;

	public ServerCommandDispatcher(SessionManager sessionManager) {
		this.sessionManager = sessionManager;
	}

	/** Dispatch a command against the session's decompiler. */
	public Object dispatch(String command, Map<String, Object> args, AnalysisSession session) throws Exception {
		if (!CommandDispatch.isKnown(command)) {
			throw new IllegalArgumentException("Unknown command: " + command);
		}
		JadxDecompiler decompiler = session.getDecompiler();
		return CommandDispatch.run(command, args, decompiler);
	}

	public boolean isReadOnlyCommand(String command) {
		return CommandDispatch.isKnown(command) && CommandDispatch.isReadOnly(command);
	}

	public boolean hasCommand(String command) {
		return CommandDispatch.isKnown(command);
	}
}
