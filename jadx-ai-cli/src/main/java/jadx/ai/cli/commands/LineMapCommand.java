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
		if (node instanceof JavaVariable) {
			return "variable";
		}
		if (node instanceof JavaPackage) {
			return "package";
		}
		return "unknown";
	}

	static class LineMapResult {
		String className;
		List<LineMapping> lineMap;
		List<AnnotationInfo> annotations;
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
}
