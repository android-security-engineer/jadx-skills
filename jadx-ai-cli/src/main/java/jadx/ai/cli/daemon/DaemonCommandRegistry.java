package jadx.ai.cli.daemon;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

public class DaemonCommandRegistry {

	private final Map<String, Function<Map<String, Object>, Object>> handlers = new HashMap<>();

	public void register(String commandName, Function<Map<String, Object>, Object> handler) {
		handlers.put(commandName, handler);
	}

	public boolean hasCommand(String commandName) {
		return handlers.containsKey(commandName);
	}

	public Object execute(String commandName, Map<String, Object> args) throws Exception {
		Function<Map<String, Object>, Object> handler = handlers.get(commandName);
		if (handler == null) {
			throw new IllegalArgumentException("Unknown command: " + commandName);
		}
		return handler.apply(args);
	}

	public Set<String> getCommandNames() {
		return handlers.keySet();
	}
}