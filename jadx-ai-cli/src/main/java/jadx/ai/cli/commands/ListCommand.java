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

@Command(name = "list", description = "List packages, classes, methods, or fields")
public class ListCommand extends AbstractCommand {

	@Option(names = { "-t", "--type" }, description = "List type: packages, classes, methods, fields", defaultValue = "classes")
	protected String listType;

	@Option(names = { "-p", "--package" }, description = "Filter by package name")
	protected String packageName;

	@Option(names = { "-c", "--class" }, description = "List methods/fields of this class")
	protected String className;

	@Option(names = { "-v", "--verbose" }, description = "Show detailed package info")
	protected boolean verbose;

	@Option(names = { "--with-inners" }, description = "Include inner classes in listing")
	protected boolean withInners;

	@Option(
			names = { "--use-index" },
			description = "Answer `list -t classes` from the on-disk symbol index (built by `index build`) "
					+ "without loading the decompiler. For other list types it warms the index as a "
					+ "side-effect. Falls back to the decompiler when no valid index exists."
	)
	protected boolean useIndex;

	/**
	 * Skip loading the decompiler when {@code --use-index} is set and a valid index can serve the request
	 * (currently {@code -t classes}). Every other case loads the decompiler as usual, preserving behaviour.
	 */
	@Override
	protected boolean requiresDecompiler() {
		return !canUseIndex();
	}

	private boolean canUseIndex() {
		if (!useIndex || inputFile == null || listType == null) {
			return false;
		}
		if (!listType.equalsIgnoreCase("classes")) {
			return false;
		}
		return indexStore().isValid();
	}

	private jadx.ai.cli.index.SymbolIndexStore indexStore() {
		return jadx.ai.cli.index.SymbolIndexStore.forInput(inputFile);
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		if (decompiler == null) {
			// Index fast-path: a valid index is present and the list type is index-serviceable.
			return listClassesViaIndex();
		}
		// Warm the index whenever the decompiler had to load with --use-index, so later opens reuse it.
		if (useIndex && inputFile != null) {
			autoBuildIndex(decompiler);
		}
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
		if (verbose) {
			List<PackageDetailInfo> results = new ArrayList<>();
			for (JavaPackage pkg : decompiler.getPackages()) {
				if (packageName != null && !pkg.getFullName().startsWith(packageName)) {
					continue;
				}
				PackageDetailInfo info = new PackageDetailInfo();
				info.fullName = pkg.getFullName();
				info.name = pkg.getName();
				info.rawName = pkg.getRawName();
				info.rawFullName = pkg.getRawFullName();
				info.classCount = pkg.getClasses().size();
				info.isLeaf = pkg.isLeaf();
				info.subPackageCount = pkg.getSubPackages().size();
				results.add(info);
			}
			return JsonOutput.list(results);
		}
		List<String> packages = decompiler.getPackages()
				.stream()
				.map(pkg -> pkg.getName())
				.filter(p -> packageName == null || p.startsWith(packageName))
				.sorted()
				.collect(Collectors.toList());
		return JsonOutput.list(packages);
	}

	/**
	 * Answer {@code list -t classes} by streaming the on-disk index (no decompiler loaded). The class
	 * table stores [full, simple, pkg, raw, isInner, access], so every {@link ClassInfo} field is
	 * reproduced exactly — including {@code isInner}/{@code accessStr} — for full parity with the
	 * decompiler path. The {@code isInner} column also lets {@code --with-inners} be honoured faithfully.
	 */
	private Object listClassesViaIndex() throws Exception {
		jadx.ai.cli.index.SymbolIndexStore store = indexStore();
		List<ClassInfo> results = new ArrayList<>();
		for (jadx.ai.cli.index.SymbolIndexStore.Row row : store.query(
				jadx.ai.cli.index.SymbolIndexStore.Kind.CLASS,
				c -> {
					boolean inner = "true".equals(c.length > 4 ? c[4] : "false");
					if (!withInners && inner) {
						return false;
					}
					String pkg = c.length > 2 ? c[2] : "";
					return packageName == null || (pkg != null && pkg.startsWith(packageName));
				},
				Integer.MAX_VALUE)) {
			ClassInfo info = new ClassInfo();
			info.fullName = row.col(0);
			info.simpleName = row.col(1);
			info.packageName = row.col(2);
			info.isInner = "true".equals(row.col(4));
			info.accessStr = row.col(5);
			results.add(info);
		}
		return JsonOutput.list(results);
	}

	/**
	 * Persist the symbol index (symbols only, no strings) as a side-effect of a decompiler-backed run so
	 * subsequent invocations can answer from disk. Best-effort: never affects the current result.
	 */
	private void autoBuildIndex(JadxDecompiler decompiler) {
		try {
			jadx.ai.cli.index.SymbolIndexStore store = indexStore();
			if (store.needsRebuild(false)) {
				store.build(decompiler, false);
			}
		} catch (Exception e) {
			// Index is an optimization; the list is still fully answered from the decompiler.
		}
	}

	private Object listClasses(JadxDecompiler decompiler) {
		List<ClassInfo> results = new ArrayList<>();
		List<JavaClass> classes = withInners ? decompiler.getClassesWithInners() : decompiler.getClasses();
		for (JavaClass cls : classes) {
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

	static class PackageDetailInfo {
		String fullName;
		String name;
		String rawName;
		String rawFullName;
		int classCount;
		boolean isLeaf;
		int subPackageCount;
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
