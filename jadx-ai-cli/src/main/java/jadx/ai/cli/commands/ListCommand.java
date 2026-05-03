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

@Command(name = "list", description = "List packages, classes, methods, or fields")
public class ListCommand extends AbstractCommand {

	@Option(names = { "-t", "--type" }, description = "List type: packages, classes, methods, fields", defaultValue = "classes")
	protected String listType;

	@Option(names = { "-p", "--package" }, description = "Filter by package name")
	protected String packageName;

	@Option(names = { "-c", "--class" }, description = "List methods/fields of this class")
	protected String className;

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		switch (listType.toLowerCase()) {
			case "packages":
				return listPackages(decompiler);
			case "classes":
				return listClasses(decompiler);
			case "methods":
				return listMethods(decompiler);
			case "fields":
				return listFields(decompiler);
			default:
				return JsonOutput.error("InvalidListType",
						"Unknown list type: " + listType + ". Use: packages, classes, methods, fields");
		}
	}

	private Object listPackages(JadxDecompiler decompiler) {
		List<String> packages = decompiler.getPackages()
				.stream()
				.map(pkg -> pkg.getName())
				.filter(p -> packageName == null || p.startsWith(packageName))
				.sorted()
				.collect(Collectors.toList());
		return JsonOutput.list(packages);
	}

	private Object listClasses(JadxDecompiler decompiler) {
		List<ClassInfo> results = new ArrayList<>();
		for (JavaClass cls : decompiler.getClasses()) {
			if (packageName != null && !cls.getPackage().startsWith(packageName)) {
				continue;
			}
			ClassInfo info = new ClassInfo();
			info.fullName = cls.getFullName();
			info.simpleName = cls.getName();
			info.packageName = cls.getPackage();
			info.isInner = cls.isInner();
			info.accessStr = cls.getAccessInfo().toString();
			results.add(info);
		}
		return JsonOutput.list(results);
	}

	private Object listMethods(JadxDecompiler decompiler) {
		if (className == null) {
			return JsonOutput.error("MissingClass", "--class is required for listing methods");
		}
		JavaClass cls = decompiler.searchJavaClassByOrigFullName(className);
		if (cls == null) {
			return JsonOutput.error("ClassNotFound", "Class not found: " + className);
		}
		List<MethodInfo> results = new ArrayList<>();
		for (JavaMethod m : cls.getMethods()) {
			MethodInfo info = new MethodInfo();
			info.name = m.getName();
			info.returnType = m.getReturnType().toString();
			results.add(info);
		}
		return JsonOutput.list(results);
	}

	private Object listFields(JadxDecompiler decompiler) {
		if (className == null) {
			return JsonOutput.error("MissingClass", "--class is required for listing fields");
		}
		JavaClass cls = decompiler.searchJavaClassByOrigFullName(className);
		if (cls == null) {
			return JsonOutput.error("ClassNotFound", "Class not found: " + className);
		}
		List<FieldInfo> results = new ArrayList<>();
		for (JavaField f : cls.getFields()) {
			FieldInfo info = new FieldInfo();
			info.name = f.getName();
			info.type = f.getType().toString();
			results.add(info);
		}
		return JsonOutput.list(results);
	}

	static class ClassInfo {
		String fullName;
		String simpleName;
		String packageName;
		boolean isInner;
		String accessStr;
	}

	static class MethodInfo {
		String name;
		String returnType;
	}

	static class FieldInfo {
		String name;
		String type;
	}
}
