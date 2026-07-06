package jadx.ai.cli.util;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import jadx.ai.cli.output.JsonOutput;

/**
 * Helper for invoking external command-line tools (apktool, frida, adb, ...) from adapter
 * commands. Locates the binary on PATH (or via a {@code JADX_AI_<TOOL>_PATH} override), runs it
 * with a timeout, drains stdout/stderr without deadlocking, and degrades gracefully to a
 * {@code ToolNotInstalled} error when the binary is absent.
 */
public final class ExternalTool {

	private ExternalTool() {
	}

	/** Result of running an external process. */
	public static final class Result {
		public boolean ran;
		public int exitCode;
		public String stdout = "";
		public String stderr = "";
		public boolean timedOut;
	}

	/**
	 * Locate an executable. Resolution order:
	 * <ol>
	 *   <li>{@code JADX_AI_<TOOL>_PATH} env var (tool upper-cased, non-alphanumerics -&gt; '_')</li>
	 *   <li>an absolute/relative path that already points at an existing file</li>
	 *   <li>each entry on {@code PATH}, trying the bare name and common executable suffixes</li>
	 * </ol>
	 */
	public static Optional<String> locate(String binary) {
		String envOverride = System.getenv(envVarName(binary));
		if (envOverride != null && !envOverride.isEmpty()) {
			File f = new File(envOverride);
			if (f.isFile() && f.canExecute()) {
				return Optional.of(f.getAbsolutePath());
			}
			// honour an explicit override even if not flagged executable
			if (f.isFile()) {
				return Optional.of(f.getAbsolutePath());
			}
		}

		File direct = new File(binary);
		if (direct.isFile()) {
			return Optional.of(direct.getAbsolutePath());
		}

		String pathEnv = System.getenv("PATH");
		if (pathEnv == null || pathEnv.isEmpty()) {
			return Optional.empty();
		}
		boolean windows = System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
		String[] suffixes = windows
				? new String[] { "", ".exe", ".bat", ".cmd" }
				: new String[] { "" };
		for (String dir : pathEnv.split(File.pathSeparator)) {
			if (dir.isEmpty()) {
				continue;
			}
			for (String suffix : suffixes) {
				File candidate = new File(dir, binary + suffix);
				if (candidate.isFile()) {
					return Optional.of(candidate.getAbsolutePath());
				}
			}
		}
		return Optional.empty();
	}

	/**
	 * Run {@code binary} with the given args. The binary is resolved via {@link #locate(String)};
	 * if it cannot be found, {@link Result#ran} is false. On timeout the process is forcibly
	 * destroyed and {@link Result#timedOut} is set.
	 */
	public static Result run(String binary, List<String> args, long timeoutMs, File workdir) {
		Result result = new Result();
		Optional<String> resolved = locate(binary);
		if (resolved.isEmpty()) {
			result.ran = false;
			return result;
		}

		List<String> cmd = new ArrayList<>();
		cmd.add(resolved.get());
		if (args != null) {
			cmd.addAll(args);
		}
		ProcessBuilder pb = new ProcessBuilder(cmd);
		if (workdir != null) {
			pb.directory(workdir);
		}
		try {
			Process process = pb.start();
			StreamCollector outCollector = new StreamCollector(process.getInputStream());
			StreamCollector errCollector = new StreamCollector(process.getErrorStream());
			Thread outThread = new Thread(outCollector, "external-tool-stdout");
			Thread errThread = new Thread(errCollector, "external-tool-stderr");
			outThread.setDaemon(true);
			errThread.setDaemon(true);
			outThread.start();
			errThread.start();

			boolean finished = process.waitFor(timeoutMs, TimeUnit.MILLISECONDS);
			if (!finished) {
				process.destroyForcibly();
				result.timedOut = true;
			}
			outThread.join(2000);
			errThread.join(2000);

			result.ran = true;
			result.exitCode = finished ? process.exitValue() : -1;
			result.stdout = outCollector.text();
			result.stderr = errCollector.text();
			return result;
		} catch (IOException e) {
			result.ran = true;
			result.exitCode = -1;
			result.stderr = "Failed to start " + binary + ": " + e.getMessage();
			return result;
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			result.ran = true;
			result.exitCode = -1;
			result.stderr = "Interrupted while running " + binary;
			return result;
		}
	}

	/**
	 * Convenience wrapper: run the tool and return a {@link JsonOutput}. Returns
	 * {@code JsonOutput.error("ToolNotInstalled", ...)} when the binary is absent, and otherwise
	 * {@code JsonOutput.ok(map)} carrying exit code and captured output.
	 */
	public static Object runOrToolMissing(String binary, List<String> args, long timeoutMs, File workdir) {
		Result r = run(binary, args, timeoutMs, workdir);
		if (!r.ran) {
			return JsonOutput.error("ToolNotInstalled",
					binary + " not found on PATH. Install it or set " + envVarName(binary)
							+ " to its full path.");
		}
		Map<String, Object> data = new HashMap<>();
		data.put("tool", binary);
		data.put("exitCode", r.exitCode);
		data.put("timedOut", r.timedOut);
		data.put("stdout", r.stdout);
		data.put("stderr", r.stderr);
		if (r.timedOut) {
			return JsonOutput.error("ToolTimeout", binary + " timed out after " + timeoutMs + "ms");
		}
		return JsonOutput.ok(data);
	}

	static String envVarName(String binary) {
		StringBuilder sb = new StringBuilder("JADX_AI_");
		for (char c : binary.toUpperCase(Locale.ROOT).toCharArray()) {
			sb.append(Character.isLetterOrDigit(c) ? c : '_');
		}
		sb.append("_PATH");
		return sb.toString();
	}

	private static final class StreamCollector implements Runnable {
		private final InputStream in;
		private final StringBuilder sb = new StringBuilder();

		StreamCollector(InputStream in) {
			this.in = in;
		}

		@Override
		public void run() {
			byte[] buf = new byte[8192];
			int n;
			try {
				while ((n = in.read(buf)) != -1) {
					sb.append(new String(buf, 0, n, StandardCharsets.UTF_8));
				}
			} catch (IOException ignored) {
				// stream closed on process exit
			}
		}

		String text() {
			return sb.toString();
		}
	}
}
