package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.api.JavaField;
import jadx.api.JavaMethod;
import jadx.api.data.ICodeComment;
import jadx.api.data.impl.JadxCodeData;

@Command(name = "search", description = "Search for classes, methods, fields, strings, resources, code, or comments")
public class SearchCommand extends AbstractCommand {

	@Option(names = { "-t", "--type" }, description = "Search type: class, method, field, string, alias, resource, code, comment", required = true)
	protected String searchType;

	@Option(names = { "-q", "--query" }, description = "Search query (substring match)", required = true)
	protected String query;

	@Option(names = { "--limit" }, description = "Max results to return", defaultValue = "50")
	protected int limit;

	@Option(names = { "--exact" }, description = "Exact match instead of substring")
	protected boolean exact;

	@Option(names = { "--search-parent" }, description = "Search class or its parent if class has DONT_GENERATE flag")
	protected boolean searchParent;

	@Option(names = { "--regex" }, description = "Use regex matching instead of substring")
	protected boolean regex;

	@Option(names = { "-i", "--ignore-case" }, description = "Case-insensitive matching")
	protected boolean ignoreCase;

	@Option(names = { "-p", "--package" }, description = "Filter results by package name (substring match)")
	protected String packageFilter;

	@Option(names = { "--resource-type" }, description = "Filter resource search by type: MANIFEST, XML, ARSC, IMG, FONT, JSON, TEXT, HTML, LIB, CODE, APK, ARCHIVE, VIDEOS, SOUNDS")
	protected String resourceTypeFilter;

	@Option(names = { "--max-size" }, description = "Max resource file size in KB to search (default: 512)", defaultValue = "512")
	protected int maxResourceSizeKB;

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
			case "resource":
				return searchResources(decompiler);
			case "code":
				return searchCode(decompiler);
			case "comment":
				return searchComments(decompiler);
			default:
				return JsonOutput.error("InvalidSearchType",
						"Unknown search type: " + searchType + ". Use: class, method, field, string, alias, resource, code, comment");
		}
	}

	private Pattern pattern;

	private boolean matches(String text) {
		if (text == null) {
			return false;
		}
		if (regex) {
			if (pattern == null) {
				int flags = ignoreCase ? Pattern.CASE_INSENSITIVE : 0;
				pattern = Pattern.compile(query, flags);
			}
			return pattern.matcher(text).find();
		}
		String input = ignoreCase ? text.toLowerCase() : text;
		String q = ignoreCase ? query.toLowerCase() : query;
		if (exact) {
			return input.equals(q);
		}
		return input.contains(q);
	}

	private boolean matchesPackage(JavaClass cls) {
		if (packageFilter == null) {
			return true;
		}
		String pkg = cls.getPackage();
		if (pkg == null) {
			return false;
		}
		return ignoreCase ? pkg.toLowerCase().contains(packageFilter.toLowerCase())
				: pkg.contains(packageFilter);
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
				r.rawName = cls.getRawName();
				results.add(r);
			}
			return JsonOutput.list(results);
		}
		for (JavaClass cls : decompiler.getClasses()) {
			if (!matchesPackage(cls)) {
				continue;
			}
			if (matches(cls.getFullName()) || matches(cls.getName())
					|| matches(cls.getRawName())) {
				ClassSearchResult r = new ClassSearchResult();
				r.fullName = cls.getFullName();
				r.simpleName = cls.getName();
				r.packageName = cls.getPackage();
				r.rawName = cls.getRawName();
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
			if (!matchesPackage(cls)) {
				continue;
			}
			for (JavaMethod m : cls.getMethods()) {
				if (matches(m.getName()) || matches(m.getFullName())) {
					MethodSearchResult r = new MethodSearchResult();
					r.className = cls.getFullName();
					r.methodName = m.getName();
					r.returnType = m.getReturnType().toString();
					r.fullId = m.getFullName();
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
			if (!matchesPackage(cls)) {
				continue;
			}
			for (JavaField f : cls.getFields()) {
				if (matches(f.getName()) || matches(f.getFullName())
						|| matches(f.getRawName())) {
					FieldSearchResult r = new FieldSearchResult();
					r.className = cls.getFullName();
					r.fieldName = f.getName();
					r.type = f.getType().toString();
					r.rawName = f.getRawName();
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
			if (!matchesPackage(cls)) {
				continue;
			}
			String code = cls.getCode();
			if (code != null && matches(code)) {
				for (String line : code.split("\n")) {
					if (matches(line)) {
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
			r.rawName = aliasCls.getRawName();
			results.add(r);
		}
		return JsonOutput.list(results);
	}

	private Object searchCode(JadxDecompiler decompiler) {
		List<CodeSearchResult> results = new ArrayList<>();
		for (JavaClass cls : decompiler.getClasses()) {
			if (!matchesPackage(cls)) {
				continue;
			}
			String code = cls.getCode();
			if (code == null) {
				continue;
			}
			String[] lines = code.split("\n");
			for (int i = 0; i < lines.length; i++) {
				if (matches(lines[i])) {
					CodeSearchResult r = new CodeSearchResult();
					r.className = cls.getFullName();
					r.lineNumber = i + 1;
					r.matchingLine = lines[i].trim();
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

	private Object searchComments(JadxDecompiler decompiler) {
		List<CommentSearchResult> results = new ArrayList<>();
		JadxCodeData codeData = (JadxCodeData) jadxArgs.getCodeData();
		if (codeData == null) {
			return JsonOutput.list(results);
		}
		for (ICodeComment comment : codeData.getComments()) {
			if (matches(comment.getComment())) {
				CommentSearchResult r = new CommentSearchResult();
				r.nodeRef = comment.getNodeRef().toString();
				r.comment = comment.getComment();
				r.style = comment.getStyle().name();
				if (comment.getCodeRef() != null) {
					r.codeRef = comment.getCodeRef().toString();
				}
				results.add(r);
				if (results.size() >= limit) {
					break;
				}
			}
		}
		return JsonOutput.list(results);
	}

	private Object searchResources(JadxDecompiler decompiler) {
		List<ResourceSearchResult> results = new ArrayList<>();
		for (var res : decompiler.getResources()) {
			if (resourceTypeFilter != null) {
				try {
					jadx.api.ResourceType filterType = jadx.api.ResourceType.valueOf(resourceTypeFilter.toUpperCase());
					if (res.getType() != filterType) {
						continue;
					}
				} catch (IllegalArgumentException e) {
					return JsonOutput.error("InvalidResourceType",
							"Unknown resource type: " + resourceTypeFilter);
				}
			}
			String resName = res.getOriginalName();
			if (!matches(resName) && !matches(res.getDeobfName())) {
				continue;
			}
			ResourceSearchResult r = new ResourceSearchResult();
			r.name = resName;
			r.type = res.getType().name();
			r.deobfName = res.getDeobfName();
			try {
				var container = res.loadContent();
				if (container != null
						&& ("TEXT".equals(container.getDataType().name())
							|| "RES_TABLE".equals(container.getDataType().name()))) {
					String text = container.getText().toString();
					if (text.length() > maxResourceSizeKB * 1024) {
						r.matchingSnippet = "Resource too large (" + (text.length() / 1024) + "KB), skipped. Use --max-size to increase.";
					} else {
						List<String> matchingLines = new ArrayList<>();
						for (String line : text.split("\n")) {
							if (matches(line)) {
								matchingLines.add(line.trim());
								if (matchingLines.size() >= 10) {
									break;
								}
							}
						}
						if (!matchingLines.isEmpty() || regex || exact) {
							r.matchingLines = matchingLines;
						}
					}
				}
			} catch (Exception e) {
				r.matchingSnippet = "Error reading resource: " + e.getMessage();
			}
			results.add(r);
			if (results.size() >= limit) {
				break;
			}
		}
		return JsonOutput.list(results);
	}

	static class ClassSearchResult {
		String fullName;
		String simpleName;
		String packageName;
		String rawName;
	}

	static class MethodSearchResult {
		String className;
		String methodName;
		String returnType;
		String fullId;
	}

	static class FieldSearchResult {
		String className;
		String fieldName;
		String type;
		String rawName;
	}

	static class StringSearchResult {
		String className;
		String matchingLine;
	}

	static class ResourceSearchResult {
		String name;
		String type;
		String deobfName;
		List<String> matchingLines;
		String matchingSnippet;
	}

	static class CodeSearchResult {
		String className;
		int lineNumber;
		String matchingLine;
	}

	static class CommentSearchResult {
		String nodeRef;
		String codeRef;
		String comment;
		String style;
	}
	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new HashMap<>();
		args.put("type", searchType);
		args.put("query", query);
		args.put("limit", limit);
		args.put("exact", exact);
		args.put("searchParent", searchParent);
		args.put("regex", regex);
		args.put("ignoreCase", ignoreCase);
		if (packageFilter != null) {
			args.put("package", packageFilter);
		}
		if (resourceTypeFilter != null) {
			args.put("resourceType", resourceTypeFilter);
		}
		args.put("maxSize", maxResourceSizeKB);
		return args;
	}

}
