package jadx.ai.cli.commands;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.api.JavaMethod;

/**
 * Renders the Dalvik bytecode (smali) for a class or a single method — the layer below jadx's
 * Java decompilation. Smali is ground truth when the decompiler's Java output is suspect
 * (jadx can drop, merge, or mis-rename blocks); it is also the form {@code apktool} emits and
 * the form patchers/hook authors hand-edit. {@link JavaClass#getSmali()} is jadx's own smali
 * renderer, so no external tool is needed. Absorbed from {@code dex-analyzer-for-llm}'s
 * {@code render_method_smali} (which wraps DexKit's smali writer) — same capability, native.
 *
 * <p>Returns {@code {className, methodSmali?, fullSmali, truncated}}. When {@code --method}
 * is given, {@code methodSmali} holds just that method's body (located by short ID, e.g.
 * {@code onCreate(Landroid/os/Bundle;)V}); otherwise {@code fullSmali} holds the whole class.
 */
@Command(name = "smali",
		description = "Render smali (Dalvik bytecode) for a class or a single method")
public class SmaliCommand extends AbstractCommand {

	@Option(names = { "-c", "--class" }, description = "Full class name", required = true)
	protected String className;

	@Option(names = { "-m", "--method" }, description = "Method short ID (e.g. 'onCreate(Landroid/os/Bundle;)V') to render only that method")
	protected String methodShortId;

	@Option(names = { "--max-chars" }, description = "Cap smali output length (chars)", defaultValue = "200000")
	protected int maxChars = 200000;

	@Override
	protected void applyArgs(Map<String, Object> args) {
		this.className = (String) args.get("class");
		this.methodShortId = (String) args.get("method");
		if (args.containsKey("max-chars") && args.get("max-chars") != null) {
			this.maxChars = ((Number) args.get("max-chars")).intValue();
		}
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		JavaClass cls = decompiler.searchJavaClassByOrigFullName(className);
		if (cls == null) {
			List<JavaClass> matches = decompiler.getClasses().stream()
					.filter(c -> c.getFullName().contains(className))
					.collect(Collectors.toList());
			if (matches.isEmpty()) {
				return JsonOutput.error("ClassNotFound", "Class not found: " + className);
			}
			cls = matches.get(0);
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("className", cls.getFullName());

		if (methodShortId != null && !methodShortId.isEmpty()) {
			JavaMethod m = cls.searchMethodByShortId(methodShortId);
			if (m == null) {
				return JsonOutput.error("MethodNotFound",
						"Method not found in " + cls.getFullName() + ": " + methodShortId);
			}
			// getSmali() is class-level; isolate the method's smali block by signature markers.
			String full = cls.getSmali();
			String methodSmali = extractMethodSmali(full, m);
			data.put("methodSmali", truncate(methodSmali, maxChars));
			data.put("methodSignature", methodShortId);
			data.put("truncated", methodSmali != null && methodSmali.length() > maxChars);
		} else {
			String full = cls.getSmali();
			data.put("fullSmali", truncate(full, maxChars));
			data.put("truncated", full != null && full.length() > maxChars);
		}
		return JsonOutput.ok(data);
	}

	/**
	 * Pulls a single method's smali out of the class listing. jadx's smali writer emits each
	 * method as a {@code .method ...} ... {@code .end method} block; we find the one whose
	 * header matches the target method's name + descriptor.
	 */
	private static String extractMethodSmali(String classSmali, JavaMethod m) {
		if (classSmali == null || classSmali.isEmpty()) {
			return null;
		}
		String name = m.getName();
		// Build the smali method-descriptor fragment: ".method <access> name(argTypes)retType"
		// We match loosely on "name(" within a .method header to stay robust against access
		// modifiers and exact descriptor formatting.
		String[] lines = classSmali.split("\n", -1);
		StringBuilder out = new StringBuilder();
		boolean inMethod = false;
		boolean matched = false;
		for (String line : lines) {
			String trimmed = line.trim();
			if (trimmed.startsWith(".method")) {
				inMethod = true;
				matched = trimmed.contains(name + "(") || trimmed.endsWith(" " + name)
						|| trimmed.matches(".*\\s" + name + "\\(.*");
				if (matched) {
					out.append(line).append('\n');
				}
				continue;
			}
			if (inMethod && matched) {
				out.append(line).append('\n');
				if (trimmed.equals(".end method")) {
					return out.toString();
				}
			}
		}
		return matched ? out.toString() : null;
	}

	private static String truncate(String s, int max) {
		if (s == null) {
			return null;
		}
		return s.length() <= max ? s : s.substring(0, max) + "\n... [truncated]";
	}

	@Override
	protected String getDaemonCommandName() {
		return "smali";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new HashMap<>();
		args.put("class", className);
		if (methodShortId != null) {
			args.put("method", methodShortId);
		}
		args.put("max-chars", maxChars);
		return args;
	}
}
