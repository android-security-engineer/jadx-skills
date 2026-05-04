package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.ICodeInfo;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.api.JavaField;
import jadx.api.JavaMethod;
import jadx.api.JavaNode;
import jadx.api.JavaPackage;
import jadx.api.JavaVariable;
import jadx.api.metadata.ICodeAnnotation;

@Command(name = "line-map", description = "Get decompiled-to-source line mapping and code annotations")
public class LineMapCommand extends AbstractCommand {

	@Option(names = { "-c", "--class" }, description = "Full class name", required = true)
	protected String className;

	@Option(names = { "--annotations" }, description = "Include code annotations (node refs at each position)")
	protected boolean includeAnnotations;

	@Option(names = { "--usage-map" }, description = "Include usage map (position to node)")
	protected boolean includeUsageMap;

	@Option(names = { "--use-places" }, description = "Show use places for a specific node (format: class.method or class.field)")
	protected String usePlacesNode;

	@Option(names = { "--source-line" }, description = "Get source line for a specific decompiled line number")
	protected int sourceLine = -1;

	@Option(names = { "--node-at" }, description = "Get JavaNode at exact position (character offset)")
	protected int nodeAtPos = -1;

	@Option(names = { "--closest-node" }, description = "Get closest JavaNode above position (character offset)")
	protected int closestNodePos = -1;

	@Option(names = { "--enclosing-node" }, description = "Get enclosing node (class/method) at position (character offset)")
	protected int enclosingNodePos = -1;

	@Option(names = { "--annotation-at" }, description = "Get code annotation at position (character offset)")
	protected int annotationAtPos = -1;

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		JavaClass cls = decompiler.searchJavaClassByOrigFullName(className);
		if (cls == null) {
			List<JavaClass> matches = decompiler.getClasses()
					.stream()
					.filter(c -> c.getFullName().contains(className))
					.collect(Collectors.toList());
			if (matches.isEmpty()) {
				return JsonOutput.error("ClassNotFound", "Class not found: " + className);
			}
			if (matches.size() > 1) {
				List<String> names = matches.stream()
						.map(JavaClass::getFullName)
						.collect(Collectors.toList());
				return JsonOutput.error("AmbiguousClass",
						"Multiple classes match. Specify full name: " + names);
			}
			cls = matches.get(0);
		}

		ICodeInfo codeInfo = cls.getCodeInfo();
		LineMapResult result = new LineMapResult();
		result.className = cls.getFullName();

		Map<Integer, Integer> lineMapping = codeInfo.getCodeMetadata().getLineMapping();
		result.lineMap = new ArrayList<>();
		for (Map.Entry<Integer, Integer> entry : lineMapping.entrySet()) {
			LineMapping lm = new LineMapping();
			lm.decompiledLine = entry.getKey();
			lm.sourceLine = entry.getValue();
			result.lineMap.add(lm);
		}

		if (includeAnnotations) {
			result.annotations = new ArrayList<>();
			Map<Integer, ICodeAnnotation> annMap = codeInfo.getCodeMetadata().getAsMap();
			for (Map.Entry<Integer, ICodeAnnotation> entry : annMap.entrySet()) {
				AnnotationInfo annInfo = new AnnotationInfo();
				annInfo.position = entry.getKey();
				annInfo.type = entry.getValue().getAnnType().name();
				JavaNode node = decompiler.getJavaNodeByCodeAnnotation(codeInfo, entry.getValue());
				if (node != null) {
					annInfo.nodeFullName = node.getFullName();
					annInfo.nodeType = getNodeType(node);
				}
				result.annotations.add(annInfo);
			}
		}

		if (includeUsageMap) {
			result.usageMap = new ArrayList<>();
			Map<Integer, JavaNode> usageMap = cls.getUsageMap();
			for (Map.Entry<Integer, JavaNode> entry : usageMap.entrySet()) {
				UsageMapEntry e = new UsageMapEntry();
				e.position = entry.getKey();
				if (entry.getValue() != null) {
					e.nodeFullName = entry.getValue().getFullName();
					e.nodeType = getNodeType(entry.getValue());
				}
				result.usageMap.add(e);
			}
		}

		if (nodeAtPos >= 0) {
			JavaNode node = decompiler.getJavaNodeAtPosition(codeInfo, nodeAtPos);
			result.nodeAtPosition = buildNodeRef(node);
		}

		if (closestNodePos >= 0) {
			JavaNode node = decompiler.getClosestJavaNode(codeInfo, closestNodePos);
			result.closestNode = buildNodeRef(node);
		}

		if (enclosingNodePos >= 0) {
			JavaNode node = decompiler.getEnclosingNode(codeInfo, enclosingNodePos);
			result.enclosingNode = buildNodeRef(node);
		}

		if (annotationAtPos >= 0) {
			ICodeAnnotation ann = cls.getAnnotationAt(annotationAtPos);
			if (ann != null) {
				AnnotationAtResult annResult = new AnnotationAtResult();
				annResult.position = annotationAtPos;
				annResult.type = ann.getAnnType().name();
				JavaNode node = decompiler.getJavaNodeByCodeAnnotation(codeInfo, ann);
				if (node != null) {
					annResult.nodeFullName = node.getFullName();
					annResult.nodeType = getNodeType(node);
				}
				result.annotationAt = annResult;
			}
		}

		return JsonOutput.ok(result);
	}

	private NodeRef buildNodeRef(JavaNode node) {
		if (node == null) {
			return null;
		}
		NodeRef ref = new NodeRef();
		ref.fullName = node.getFullName();
		ref.nodeType = getNodeType(node);
		ref.defPos = node.getDefPos();
		if (node.getDeclaringClass() != null) {
			ref.declaringClass = node.getDeclaringClass().getFullName();
		}
		return ref;
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
		if (node instanceof JavaVariable) {
			return "variable";
		}
		if (node instanceof JavaPackage) {
			return "package";
		}
		return "unknown";
	}

	static class UsageMapEntry {
		int position;
		String nodeFullName;
		String nodeType;
	}

	static class LineMapResult {
		String className;
		List<LineMapping> lineMap;
		List<AnnotationInfo> annotations;
		List<UsageMapEntry> usageMap;
		List<Integer> usePlaces;
		Integer sourceLineResult;
		NodeRef nodeAtPosition;
		NodeRef closestNode;
		NodeRef enclosingNode;
		AnnotationAtResult annotationAt;
	}

	static class LineMapping {
		int decompiledLine;
		int sourceLine;
	}

	static class AnnotationInfo {
		int position;
		String type;
		String nodeFullName;
		String nodeType;
	}

	static class NodeRef {
		String fullName;
		String nodeType;
		int defPos;
		String declaringClass;
	}

	static class AnnotationAtResult {
		int position;
		String type;
		String nodeFullName;
		String nodeType;
	}
}
