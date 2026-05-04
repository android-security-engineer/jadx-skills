package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.List;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.api.JavaField;
import jadx.api.JavaMethod;

@Command(name = "search", description = "Search for classes, methods, fields, or strings")
public class SearchCommand extends AbstractCommand {

	@Option(names = { "-t", "--type" }, description = "Search type: class, method, field, string, alias", required = true)
	protected String searchType;

	@Option(names = { "-q", "--query" }, description = "Search query (substring match)", required = true)
	protected String query;

	@Option(names = { "--limit" }, description = "Max results to return", defaultValue = "50")
	protected int limit;

	@Option(names = { "--exact" }, description = "Exact match instead of substring")
	protected boolean exact;

	@Option(names = { "--search-parent" }, description = "Search class or its parent if class has DONT_GENERATE flag")
	protected boolean searchParent;

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		switch (searchType.toLowerCase()) {
			case "class":
				return searchClasses(decompiler);
			case "method":
				return searchMethods(decompiler);
			case "field":
				return searchFields(decompiler);
			case "string":
				return searchStrings(decompiler);
			case "alias":
				return searchByAlias(decompiler);
			default:
				return JsonOutput.error("InvalidSearchType",
						"Unknown search type: " + searchType + ". Use: class, method, field, string, alias");
		}
	}

	private boolean matches(String text) {
		if (text == null) {
			return false;
		}
		if (exact) {
			return text.equals(query);
		}
		return text.contains(query);
	}

	private Object searchClasses(JadxDecompiler decompiler) {
		List<ClassSearchResult> results = new ArrayList<>();
		if (searchParent) {
			JavaClass cls = decompiler.searchJavaClassOrItsParentByOrigFullName(query);
			if (cls != null) {
				ClassSearchResult r = new ClassSearchResult();
				r.fullName = cls.getFullName();
				r.simpleName = cls.getName();
				r.packageName = cls.getPackage();
				results.add(r);
			}
			return JsonOutput.list(results);
		}
		for (JavaClass cls : decompiler.getClasses()) {
			if (matches(cls.getFullName()) || matches(cls.getName())) {
				ClassSearchResult r = new ClassSearchResult();
				r.fullName = cls.getFullName();
				r.simpleName = cls.getName();
				r.packageName = cls.getPackage();
				results.add(r);
				if (results.size() >= limit) {
					break;
				}
			}
		}
		return JsonOutput.list(results);
	}

	private Object searchMethods(JadxDecompiler decompiler) {
		List<MethodSearchResult> results = new ArrayList<>();
		for (JavaClass cls : decompiler.getClasses()) {
			for (JavaMethod m : cls.getMethods()) {
				if (matches(m.getName())) {
					MethodSearchResult r = new MethodSearchResult();
					r.className = cls.getFullName();
					r.methodName = m.getName();
					r.returnType = m.getReturnType().toString();
					results.add(r);
					if (results.size() >= limit) {
						break;
					}
				}
			}
			if (results.size() >= limit) {
				break;
			}
		}
		return JsonOutput.list(results);
	}

	private Object searchFields(JadxDecompiler decompiler) {
		List<FieldSearchResult> results = new ArrayList<>();
		for (JavaClass cls : decompiler.getClasses()) {
			for (JavaField f : cls.getFields()) {
				if (matches(f.getName())) {
					FieldSearchResult r = new FieldSearchResult();
					r.className = cls.getFullName();
					r.fieldName = f.getName();
					r.type = f.getType().toString();
					results.add(r);
					if (results.size() >= limit) {
						break;
					}
				}
			}
			if (results.size() >= limit) {
				break;
			}
		}
		return JsonOutput.list(results);
	}

	private Object searchStrings(JadxDecompiler decompiler) {
		List<StringSearchResult> results = new ArrayList<>();
		for (JavaClass cls : decompiler.getClasses()) {
			String code = cls.getCode();
			if (code != null && matches(code)) {
				for (String line : code.split("\n")) {
					if (line.contains(query)) {
						StringSearchResult r = new StringSearchResult();
						r.className = cls.getFullName();
						r.matchingLine = line.trim();
						results.add(r);
						if (results.size() >= limit) {
							break;
						}
					}
				}
			}
			if (results.size() >= limit) {
				break;
			}
		}
		return JsonOutput.list(results);
	}

	private Object searchByAlias(JadxDecompiler decompiler) {
		List<ClassSearchResult> results = new ArrayList<>();
		JavaClass aliasCls = decompiler.searchJavaClassByAliasFullName(query);
		if (aliasCls != null) {
			ClassSearchResult r = new ClassSearchResult();
			r.fullName = aliasCls.getFullName();
			r.simpleName = aliasCls.getName();
			r.packageName = aliasCls.getPackage();
			results.add(r);
		}
		return JsonOutput.list(results);
	}

	static class ClassSearchResult {
		String fullName;
		String simpleName;
		String packageName;
	}

	static class MethodSearchResult {
		String className;
		String methodName;
		String returnType;
	}

	static class FieldSearchResult {
		String className;
		String fieldName;
		String type;
	}

	static class StringSearchResult {
		String className;
		String matchingLine;
	}
}
