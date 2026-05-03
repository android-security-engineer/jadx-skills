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
import jadx.api.JavaNode;

@Command(name = "usage", description = "Query usage relationships (call graph, references)")
public class UsageCommand extends AbstractCommand {

	@Option(names = { "-c", "--class" }, description = "Class name to query usage for")
	protected String className;

	@Option(names = { "-m", "--method" }, description = "Method name to query usage for (requires --class)")
	protected String methodName;

	@Option(names = { "-f", "--field" }, description = "Field name to query usage for (requires --class)")
	protected String fieldName;

	@Option(names = { "-t", "--type" }, description = "Query type: useIn (who uses this) or used (what this uses)", defaultValue = "useIn")
	protected String queryType;

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		if (className == null) {
			return JsonOutput.error("MissingClass", "--class is required");
		}
		JavaClass cls = decompiler.searchJavaClassByOrigFullName(className);
		if (cls == null) {
			List<JavaClass> matches = decompiler.getClasses()
					.stream()
					.filter(c -> c.getFullName().contains(className))
					.collect(Collectors.toList());
			if (matches.isEmpty()) {
				return JsonOutput.error("ClassNotFound", "Class not found: " + className);
			}
			cls = matches.get(0);
		}

		if (methodName != null) {
			return queryMethodUsage(cls, methodName);
		}
		if (fieldName != null) {
			return queryFieldUsage(cls, fieldName);
		}
		return queryClassUsage(cls);
	}

	private Object queryClassUsage(JavaClass cls) {
		cls.getCode();
		List<UsageRef> refs = new ArrayList<>();
		for (JavaNode node : cls.getUseIn()) {
			UsageRef ref = new UsageRef();
			ref.name = node.getFullName();
			ref.nodeType = getNodeType(node);
			refs.add(ref);
		}
		UsageResult result = new UsageResult();
		result.target = cls.getFullName();
		result.targetType = "class";
		result.references = refs;
		return JsonOutput.ok(result);
	}

	private Object queryMethodUsage(JavaClass cls, String mthName) {
		cls.getCode();
		List<JavaMethod> methods = cls.getMethods()
				.stream()
				.filter(m -> m.getName().equals(mthName))
				.collect(Collectors.toList());
		if (methods.isEmpty()) {
			return JsonOutput.error("MethodNotFound", "Method not found: " + mthName);
		}
		JavaMethod mth = methods.get(0);
		List<UsageRef> refs = new ArrayList<>();
		List<JavaNode> nodes = "used".equals(queryType) ? mth.getUsed() : mth.getUseIn();
		for (JavaNode node : nodes) {
			UsageRef ref = new UsageRef();
			ref.name = node.getFullName();
			ref.nodeType = getNodeType(node);
			refs.add(ref);
		}
		UsageResult result = new UsageResult();
		result.target = mth.getFullName();
		result.targetType = "method";
		result.queryType = queryType;
		result.references = refs;
		result.overrideRelatedMethods = new ArrayList<>();
		for (JavaMethod override : mth.getOverrideRelatedMethods()) {
			result.overrideRelatedMethods.add(override.getFullName());
		}
		result.callsSelf = mth.callsSelf();
		return JsonOutput.ok(result);
	}

	private Object queryFieldUsage(JavaClass cls, String fldName) {
		cls.getCode();
		JavaField target = null;
		for (JavaField f : cls.getFields()) {
			if (f.getName().equals(fldName)) {
				target = f;
				break;
			}
		}
		if (target == null) {
			return JsonOutput.error("FieldNotFound", "Field not found: " + fldName);
		}
		List<UsageRef> refs = new ArrayList<>();
		for (JavaNode node : target.getUseIn()) {
			UsageRef ref = new UsageRef();
			ref.name = node.getFullName();
			ref.nodeType = getNodeType(node);
			refs.add(ref);
		}
		UsageResult result = new UsageResult();
		result.target = target.getFullName();
		result.targetType = "field";
		result.references = refs;
		return JsonOutput.ok(result);
	}

	private String getNodeType(JavaNode node) {
		if (node instanceof JavaClass) {
			return "class";
		}
		if (node instanceof JavaMethod) {
			return "method";
		}
		if (node instanceof JavaField) {
			return "field";
		}
		return "unknown";
	}

	static class UsageResult {
		String target;
		String targetType;
		String queryType;
		List<UsageRef> references;
		List<String> overrideRelatedMethods;
		boolean callsSelf;
	}

	static class UsageRef {
		String name;
		String nodeType;
	}
}
