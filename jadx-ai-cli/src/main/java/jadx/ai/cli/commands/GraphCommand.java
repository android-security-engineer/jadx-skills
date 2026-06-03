package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.api.JavaMethod;
import jadx.api.JavaNode;

@Command(name = "graph", description = "Generate call graph, inheritance graph, or usage graph")
public class GraphCommand extends AbstractCommand {

	@Option(names = {"-t", "--type"}, description = "Graph type: call, inheritance, usage", defaultValue = "call")
	protected String graphType;

	@Option(names = {"-c", "--class"}, description = "Target class name (full name)")
	protected String className;

	@Option(names = {"-m", "--method"}, description = "Target method name (within class)")
	protected String methodName;

	@Option(names = {"-d", "--depth"}, description = "Max traversal depth", defaultValue = "3")
	protected int depth;

	@Option(names = {"--format"}, description = "Output format: json, mermaid, dot", defaultValue = "json")
	protected String outputFormat;

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		if (className == null && !"inheritance".equals(graphType)) {
			return JsonOutput.error("MissingClass", "--class is required for " + graphType + " graph");
		}

		switch (graphType) {
			case "call":
				return buildCallGraph(decompiler);
			case "inheritance":
				return buildInheritanceGraph(decompiler);
			case "usage":
				return buildUsageGraph(decompiler);
			default:
				return JsonOutput.error("InvalidType", "Unknown graph type: " + graphType);
		}
	}

	private Object buildCallGraph(JadxDecompiler decompiler) throws Exception {
		JavaClass cls = decompiler.searchJavaClassByOrigFullName(className);
		if (cls == null) {
			return JsonOutput.error("ClassNotFound", "Class not found: " + className);
		}

		GraphData graph = new GraphData();
		graph.type = "call";
		graph.root = cls.getFullName();

		Set<String> visited = new HashSet<>();
		collectCallGraph(cls, methodName, depth, 0, visited, graph);

		return formatGraph(graph);
	}

	private void collectCallGraph(JavaClass cls, String targetMethod, int maxDepth, int currentDepth,
			Set<String> visited, GraphData graph) {
		String clsName = cls.getFullName();
		if (currentDepth > maxDepth || !visited.add(clsName + "." + targetMethod)) {
			return;
		}

		GraphNode node = new GraphNode();
		node.id = clsName;
		node.type = "class";
		node.label = clsName;
		graph.nodes.add(node);

		for (JavaMethod m : cls.getMethods()) {
			if (targetMethod != null && !m.getName().equals(targetMethod)) {
				continue;
			}
			String methodId = clsName + "." + m.getName();
			GraphNode methodNode = new GraphNode();
			methodNode.id = methodId;
			methodNode.type = "method";
			methodNode.label = m.getName();
			graph.nodes.add(methodNode);

			GraphEdge classToMethod = new GraphEdge();
			classToMethod.source = clsName;
			classToMethod.target = methodId;
			classToMethod.type = "contains";
			graph.edges.add(classToMethod);

			for (JavaNode used : m.getUsed()) {
				String usedId;
				String usedType;
				if (used instanceof JavaMethod) {
					JavaMethod usedMethod = (JavaMethod) used;
					JavaClass parent = usedMethod.getDeclaringClass();
					usedId = parent.getFullName() + "." + usedMethod.getName();
					usedType = "method";
				} else if (used instanceof JavaClass) {
					usedId = ((JavaClass) used).getFullName();
					usedType = "class";
				} else {
					continue;
				}

				GraphEdge edge = new GraphEdge();
				edge.source = methodId;
				edge.target = usedId;
				edge.type = "calls";
				graph.edges.add(edge);

				if (used instanceof JavaMethod && currentDepth < maxDepth) {
					JavaMethod usedMethod = (JavaMethod) used;
					collectCallGraph(usedMethod.getDeclaringClass(), usedMethod.getName(),
							maxDepth, currentDepth + 1, visited, graph);
				}
			}
		}
	}

	private Object buildInheritanceGraph(JadxDecompiler decompiler) throws Exception {
		GraphData graph = new GraphData();
		graph.type = "inheritance";

		Set<String> visited = new HashSet<>();

		if (className != null) {
			JavaClass cls = decompiler.searchJavaClassByOrigFullName(className);
			if (cls == null) {
				return JsonOutput.error("ClassNotFound", "Class not found: " + className);
			}
			graph.root = cls.getFullName();
			collectInheritanceGraph(cls, depth, 0, visited, graph);
		} else {
			graph.root = "all";
			for (JavaClass cls : decompiler.getClasses()) {
				if (cls.getDeclaringClass() == null) {
					collectInheritanceGraph(cls, depth, 0, visited, graph);
				}
			}
		}

		return formatGraph(graph);
	}

	private void collectInheritanceGraph(JavaClass cls, int maxDepth, int currentDepth,
			Set<String> visited, GraphData graph) {
		String name = cls.getFullName();
		if (!visited.add(name)) {
			return;
		}

		GraphNode node = new GraphNode();
		node.id = name;
		node.type = "class";
		node.label = name;
		graph.nodes.add(node);

		JavaClass topParent = cls.getTopParentClass();
		if (topParent != null && !topParent.getFullName().equals(name)) {
			GraphEdge edge = new GraphEdge();
			edge.source = name;
			edge.target = topParent.getFullName();
			edge.type = "extends";
			graph.edges.add(edge);
		}

		JavaClass declaring = cls.getDeclaringClass();
		if (declaring != null) {
			GraphEdge edge = new GraphEdge();
			edge.source = declaring.getFullName();
			edge.target = name;
			edge.type = "inner";
			graph.edges.add(edge);
		}

		if (currentDepth < maxDepth) {
			for (JavaClass inner : cls.getInnerClasses()) {
				collectInheritanceGraph(inner, maxDepth, currentDepth + 1, visited, graph);
			}
			for (JavaNode useIn : cls.getUseIn()) {
				if (useIn instanceof JavaClass) {
					GraphEdge edge = new GraphEdge();
					edge.source = ((JavaClass) useIn).getFullName();
					edge.target = name;
					edge.type = "implements";
					graph.edges.add(edge);
				}
			}
		}
	}

	private Object buildUsageGraph(JadxDecompiler decompiler) throws Exception {
		JavaClass cls = decompiler.searchJavaClassByOrigFullName(className);
		if (cls == null) {
			return JsonOutput.error("ClassNotFound", "Class not found: " + className);
		}

		GraphData graph = new GraphData();
		graph.type = "usage";
		graph.root = cls.getFullName();

		GraphNode root = new GraphNode();
		root.id = cls.getFullName();
		root.type = "class";
		root.label = cls.getFullName();
		graph.nodes.add(root);

		Set<String> visited = new HashSet<>();
		visited.add(cls.getFullName());

		for (JavaNode useIn : cls.getUseIn()) {
			String useInName = useIn.getFullName();
			GraphNode useInNode = new GraphNode();
			useInNode.id = useInName;
			useInNode.type = useIn instanceof JavaMethod ? "method" : "class";
			useInNode.label = useInName;
			graph.nodes.add(useInNode);

			GraphEdge edge = new GraphEdge();
			edge.source = useInName;
			edge.target = cls.getFullName();
			edge.type = "uses";
			graph.edges.add(edge);
		}

		return formatGraph(graph);
	}

	private Object formatGraph(GraphData graph) {
		if ("mermaid".equals(outputFormat)) {
			return toMermaid(graph);
		}
		if ("dot".equals(outputFormat)) {
			return toDot(graph);
		}
		return JsonOutput.ok(graph);
	}

	private String toMermaid(GraphData graph) {
		StringBuilder sb = new StringBuilder();
		String direction = "inheritance".equals(graph.type) ? "TB" : "LR";
		sb.append("graph ").append(direction).append("\n");

		Set<String> nodeIds = new LinkedHashSet<>();
		for (GraphNode n : graph.nodes) {
			nodeIds.add(n.id);
		}
		for (String id : nodeIds) {
			String safeId = id.replace(".", "_").replace("$", "__");
			sb.append("  ").append(safeId).append("[\"").append(id).append("\"]\n");
		}
		for (GraphEdge e : graph.edges) {
			String src = e.source.replace(".", "_").replace("$", "__");
			String tgt = e.target.replace(".", "_").replace("$", "__");
			String arrow = "extends".equals(e.type) || "inner".equals(e.type) ? "-->" : "-->";
			sb.append("  ").append(src).append(" ").append(arrow).append(" ").append(tgt).append("\n");
		}
		return sb.toString();
	}

	private String toDot(GraphData graph) {
		StringBuilder sb = new StringBuilder();
		sb.append("digraph {\n");
		sb.append("  rankdir=").append("inheritance".equals(graph.type) ? "TB" : "LR").append(";\n");

		Set<String> nodeIds = new LinkedHashSet<>();
		for (GraphNode n : graph.nodes) {
			nodeIds.add(n.id);
		}
		for (String id : nodeIds) {
			sb.append("  \"").append(id).append("\";\n");
		}
		for (GraphEdge e : graph.edges) {
			sb.append("  \"").append(e.source).append("\" -> \"").append(e.target).append("\"");
			sb.append(" [label=\"").append(e.type).append("\"];\n");
		}
		sb.append("}\n");
		return sb.toString();
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new HashMap<>();
		args.put("type", graphType);
		if (className != null) {
			args.put("class", className);
		}
		if (methodName != null) {
			args.put("method", methodName);
		}
		args.put("depth", depth);
		args.put("format", outputFormat);
		return args;
	}

	static class GraphData {
		String type;
		String root;
		List<GraphNode> nodes = new ArrayList<>();
		List<GraphEdge> edges = new ArrayList<>();
	}

	static class GraphNode {
		String id;
		String type;
		String label;
	}

	static class GraphEdge {
		String source;
		String target;
		String type;
	}
}
