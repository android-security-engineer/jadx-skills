package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.api.JavaField;
import jadx.api.JavaMethod;
import jadx.api.JavaPackage;

@Command(name = "rename", description = "Rename classes, methods, fields, packages, or remove aliases")
public class RenameCommand extends AbstractCommand {

	@Option(names = { "-t", "--type" }, description = "Target type: class, method, field, package", required = true)
	protected String targetType;

	@Option(names = { "-c", "--class" }, description = "Class full name")
	protected String className;

	@Option(names = { "-m", "--method" }, description = "Method name (requires --class)")
	protected String methodName;

	@Option(names = { "-f", "--field" }, description = "Field name (requires --class)")
	protected String fieldName;

	@Option(names = { "-p", "--package" }, description = "Package full name")
	protected String packageName;

	@Option(names = { "-n", "--name" }, description = "New name (alias) to set")
	protected String newName;

	@Option(names = { "--remove-alias" }, description = "Remove alias and revert to original name")
	protected boolean removeAlias;

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		if (newName == null && !removeAlias) {
			return JsonOutput.error("MissingAction",
					"Specify --name <newName> to rename or --remove-alias to revert");
		}
		switch (targetType.toLowerCase()) {
			case "class":
				return renameClass(decompiler);
			case "method":
				return renameMethod(decompiler);
			case "field":
				return renameField(decompiler);
			case "package":
				return renamePackage(decompiler);
			default:
				return JsonOutput.error("InvalidTargetType",
						"Unknown type: " + targetType + ". Use: class, method, field, package");
		}
	}

	private JavaClass resolveClass(JadxDecompiler decompiler, String name) {
		if (name == null) {
			return null;
		}
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

	private Object renameClass(JadxDecompiler decompiler) {
		if (className == null) {
			return JsonOutput.error("MissingClass", "--class is required");
		}
		JavaClass cls = resolveClass(decompiler, className);
		if (cls == null) {
			return JsonOutput.error("ClassNotFound", "Class not found: " + className);
		}
		String oldName = cls.getFullName();
		if (removeAlias) {
			cls.removeAlias();
		}
		RenameResult result = new RenameResult();
		result.targetType = "class";
		result.oldName = oldName;
		result.newName = removeAlias ? cls.getFullName() : newName;
		result.action = removeAlias ? "removeAlias" : "rename";
		return JsonOutput.ok(result);
	}

	private Object renameMethod(JadxDecompiler decompiler) {
		if (className == null || methodName == null) {
			return JsonOutput.error("MissingParams", "--class and --method are required");
		}
		JavaClass cls = resolveClass(decompiler, className);
		if (cls == null) {
			return JsonOutput.error("ClassNotFound", "Class not found: " + className);
		}
		List<JavaMethod> methods = cls.getMethods()
				.stream()
				.filter(m -> m.getName().equals(methodName))
				.collect(Collectors.toList());
		if (methods.isEmpty()) {
			return JsonOutput.error("MethodNotFound", "Method not found: " + methodName);
		}
		List<RenameResult> results = new ArrayList<>();
		for (JavaMethod m : methods) {
			String oldName = m.getFullName();
			if (removeAlias) {
				m.removeAlias();
			}
			RenameResult r = new RenameResult();
			r.targetType = "method";
			r.oldName = oldName;
			r.newName = removeAlias ? m.getFullName() : newName;
			r.action = removeAlias ? "removeAlias" : "rename";
			results.add(r);
		}
		return JsonOutput.list(results);
	}

	private Object renameField(JadxDecompiler decompiler) {
		if (className == null || fieldName == null) {
			return JsonOutput.error("MissingParams", "--class and --field are required");
		}
		JavaClass cls = resolveClass(decompiler, className);
		if (cls == null) {
			return JsonOutput.error("ClassNotFound", "Class not found: " + className);
		}
		JavaField target = null;
		for (JavaField f : cls.getFields()) {
			if (f.getName().equals(fieldName)) {
				target = f;
				break;
			}
		}
		if (target == null) {
			return JsonOutput.error("FieldNotFound", "Field not found: " + fieldName);
		}
		String oldName = target.getFullName();
		if (removeAlias) {
			target.removeAlias();
		}
		RenameResult result = new RenameResult();
		result.targetType = "field";
		result.oldName = oldName;
		result.newName = removeAlias ? target.getFullName() : newName;
		result.action = removeAlias ? "removeAlias" : "rename";
		return JsonOutput.ok(result);
	}

	private Object renamePackage(JadxDecompiler decompiler) {
		if (packageName == null) {
			return JsonOutput.error("MissingPackage", "--package is required");
		}
		JavaPackage targetPkg = null;
		for (JavaPackage pkg : decompiler.getPackages()) {
			if (pkg.getFullName().equals(packageName)) {
				targetPkg = pkg;
				break;
			}
		}
		if (targetPkg == null) {
			return JsonOutput.error("PackageNotFound", "Package not found: " + packageName);
		}
		String oldName = targetPkg.getFullName();
		if (removeAlias) {
			targetPkg.removeAlias();
		} else {
			targetPkg.rename(newName);
		}
		RenameResult result = new RenameResult();
		result.targetType = "package";
		result.oldName = oldName;
		result.newName = removeAlias ? targetPkg.getFullName() : newName;
		result.action = removeAlias ? "removeAlias" : "rename";
		return JsonOutput.ok(result);
	}

	static class RenameResult {
		String targetType;
		String oldName;
		String newName;
		String action;
	}
}
