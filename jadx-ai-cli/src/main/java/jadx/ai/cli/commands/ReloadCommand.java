package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;

@Command(name = "reload", description = "Reload, recompile, or unload class code")
public class ReloadCommand extends AbstractCommand {

	@Option(names = { "-c", "--class" }, description = "Class full name to reload/unload")
	protected String className;

	@Option(
			names = { "-t", "--type" },
			description = "Action: reload (recompile class), unload (free code), codeData (refresh all code data)", defaultValue = "reload"
	)
	protected String actionType;

	@Option(names = { "--all" }, description = "Apply action to all classes (use with caution)")
	protected boolean allClasses;

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		switch (actionType.toLowerCase()) {
			case "reload":
				return reloadClass(decompiler);
			case "unload":
				return unloadClass(decompiler);
			case "codedata":
				decompiler.reloadCodeData();
				ReloadResult result = new ReloadResult();
				result.action = "codeData";
				result.message = "Code data reloaded for all classes";
				return JsonOutput.ok(result);
			default:
				return JsonOutput.error("InvalidAction",
						"Unknown action: " + actionType + ". Use: reload, unload, codeData");
		}
	}

	private Object reloadClass(JadxDecompiler decompiler) {
		if (allClasses) {
			List<ReloadResult> results = new ArrayList<>();
			for (JavaClass cls : decompiler.getClasses()) {
				ReloadResult r = new ReloadResult();
				r.className = cls.getFullName();
				r.action = "reload";
				try {
					cls.reload();
					r.success = true;
				} catch (Exception e) {
					r.success = false;
					r.message = e.getMessage();
				}
				results.add(r);
			}
			return JsonOutput.list(results);
		}
		if (className == null) {
			return JsonOutput.error("MissingClass", "--class or --all is required");
		}
		JavaClass cls = resolveClass(decompiler, className);
		if (cls == null) {
			return JsonOutput.error("ClassNotFound", "Class not found: " + className);
		}
		ReloadResult result = new ReloadResult();
		result.className = cls.getFullName();
		result.action = "reload";
		cls.reload();
		result.success = true;
		return JsonOutput.ok(result);
	}

	private Object unloadClass(JadxDecompiler decompiler) {
		if (allClasses) {
			List<ReloadResult> results = new ArrayList<>();
			for (JavaClass cls : decompiler.getClasses()) {
				ReloadResult r = new ReloadResult();
				r.className = cls.getFullName();
				r.action = "unload";
				cls.unload();
				r.success = true;
				results.add(r);
			}
			return JsonOutput.list(results);
		}
		if (className == null) {
			return JsonOutput.error("MissingClass", "--class or --all is required");
		}
		JavaClass cls = resolveClass(decompiler, className);
		if (cls == null) {
			return JsonOutput.error("ClassNotFound", "Class not found: " + className);
		}
		ReloadResult result = new ReloadResult();
		result.className = cls.getFullName();
		result.action = "unload";
		cls.unload();
		result.success = true;
		return JsonOutput.ok(result);
	}

	private JavaClass resolveClass(JadxDecompiler decompiler, String name) {
		JavaClass cls = decompiler.searchJavaClassByOrigFullName(name);
		if (cls == null) {
			List<JavaClass> matches = decompiler.getClasses()
					.stream()
					.filter(c -> c.getFullName().contains(name))
					.collect(Collectors.toList());
			if (matches.size() == 1) {
				return matches.get(0);
			}
		}
		return cls;
	}

	static class ReloadResult {
		String className;
		String action;
		boolean success;
		String message;
	}
}
