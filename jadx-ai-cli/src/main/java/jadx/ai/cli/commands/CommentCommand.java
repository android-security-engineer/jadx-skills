package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.api.JavaField;
import jadx.api.JavaMethod;
import jadx.api.data.CommentStyle;
import jadx.api.data.ICodeComment;
import jadx.api.data.ICodeData;
import jadx.api.data.impl.JadxCodeComment;
import jadx.api.data.impl.JadxCodeData;
import jadx.api.data.impl.JadxCodeRef;
import jadx.api.data.impl.JadxNodeRef;

@Command(name = "comment", description = "Manage code annotations and metadata comments (list/search/add/update/delete)")
public class CommentCommand extends AbstractCommand {

	@Option(names = {"-c", "--class"}, description = "Target class name (full name)", required = true)
	protected String className;

	@Option(names = {"-t", "--type"}, description = "Operation: list, search, add, update, delete", defaultValue = "list")
	protected String opType;

	@Option(names = {"-q", "--query"}, description = "Search keyword for annotations")
	protected String query;

	@Option(names = {"--comment-text"}, description = "Comment text for add/update operations")
	protected String commentText;

	@Option(names = {"-m", "--method"}, description = "Target method name")
	protected String methodName;

	@Option(names = {"-f", "--field"}, description = "Target field name")
	protected String fieldName;

	@Option(names = {"--style"}, description = "Comment style: LINE, BLOCK, BLOCK_CONDENSED, JAVADOC, JAVADOC_CONDENSED", defaultValue = "LINE")
	protected String style;

	@Option(names = {"--insn-offset"}, description = "Instruction offset (-1 = no offset)", defaultValue = "-1")
	protected int insnOffset;

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		JavaClass cls = decompiler.searchJavaClassByOrigFullName(className);
		if (cls == null) {
			return JsonOutput.error("ClassNotFound", "Class not found: " + className);
		}

		switch (opType) {
			case "list":
				return listAnnotations(cls);
			case "search":
				if (query == null) {
					return JsonOutput.error("MissingQuery", "--query is required for search");
				}
				return searchAnnotations(cls, query);
			case "add":
				return addComment(decompiler, cls);
			case "update":
				return updateComment(decompiler, cls);
			case "delete":
				return deleteComment(decompiler, cls);
			default:
				return JsonOutput.error("InvalidType", "Unknown operation: " + opType);
		}
	}

	private Object listAnnotations(JavaClass cls) throws Exception {
		var codeInfo = cls.getCodeInfo();
		if (codeInfo == null) {
			return JsonOutput.error("NoCode", "Class has no decompiled code");
		}

		List<Map<String, Object>> annotations = new ArrayList<>();
		var metadata = codeInfo.getCodeMetadata();
		if (metadata != null) {
			for (var entry : metadata) {
				Map<String, Object> ann = new HashMap<>();
				ann.put("position", entry.getKey());
				Object value = entry.getValue();
				if (value != null) {
					ann.put("node", value.toString());
					ann.put("nodeType", value.getClass().getSimpleName());
				}
				annotations.add(ann);
			}
		}

		Map<String, Object> result = new HashMap<>();
		result.put("class", cls.getFullName());
		result.put("annotationCount", annotations.size());
		result.put("annotations", annotations);
		return JsonOutput.ok(result);
	}

	private Object searchAnnotations(JavaClass cls, String keyword) throws Exception {
		var codeInfo = cls.getCodeInfo();
		if (codeInfo == null) {
			return JsonOutput.error("NoCode", "Class has no decompiled code");
		}

		List<Map<String, Object>> matching = new ArrayList<>();
		var metadata = codeInfo.getCodeMetadata();
		if (metadata != null) {
			for (var entry : metadata) {
				Object value = entry.getValue();
				if (value != null && value.toString().toLowerCase().contains(keyword.toLowerCase())) {
					Map<String, Object> ann = new HashMap<>();
					ann.put("position", entry.getKey());
					ann.put("node", value.toString());
					matching.add(ann);
				}
			}
		}

		// Also search in method/field names
		for (JavaMethod m : cls.getMethods()) {
			if (m.getName().toLowerCase().contains(keyword.toLowerCase())) {
				Map<String, Object> ann = new HashMap<>();
				ann.put("type", "method");
				ann.put("name", m.getName());
				ann.put("fullName", m.getFullName());
				matching.add(ann);
			}
		}

		Map<String, Object> result = new HashMap<>();
		result.put("class", cls.getFullName());
		result.put("query", keyword);
		result.put("matchCount", matching.size());
		result.put("matches", matching);
		return JsonOutput.ok(result);
	}

	private Object addComment(JadxDecompiler decompiler, JavaClass cls) {
		if (commentText == null || commentText.isEmpty()) {
			return JsonOutput.error("MissingCommentText", "--comment-text is required for add");
		}

		try {
			JadxNodeRef nodeRef = buildNodeRef(decompiler, cls);
			JadxCodeRef codeRef = insnOffset >= 0 ? JadxCodeRef.forInsn(insnOffset) : null;
			CommentStyle commentStyle = CommentStyle.valueOf(style.toUpperCase());
			ICodeComment comment = new JadxCodeComment(nodeRef, codeRef, commentText, commentStyle);

			JadxCodeData codeData = (JadxCodeData) jadxArgs.getCodeData();
			if (codeData == null) {
				codeData = new JadxCodeData();
				jadxArgs.setCodeData(codeData);
			}
			List<ICodeComment> comments = new ArrayList<>(codeData.getComments());
			comments.add(comment);
			Collections.sort(comments);
			codeData.setComments(comments);
			jadxArgs.setCodeData(codeData);
			decompiler.reloadCodeData();

			Map<String, Object> result = new HashMap<>();
			result.put("action", "add");
			result.put("class", className);
			result.put("nodeRef", nodeRef.toString());
			result.put("codeRef", codeRef != null ? codeRef.toString() : null);
			result.put("comment", commentText);
			result.put("style", commentStyle.name());
			return JsonOutput.ok(result);
		} catch (Exception e) {
			return JsonOutput.error("AddFailed", e.getMessage());
		}
	}

	private Object updateComment(JadxDecompiler decompiler, JavaClass cls) {
		if (commentText == null || commentText.isEmpty()) {
			return JsonOutput.error("MissingCommentText", "--comment-text is required for update");
		}

		try {
			JadxNodeRef nodeRef = buildNodeRef(decompiler, cls);
			JadxCodeRef codeRef = insnOffset >= 0 ? JadxCodeRef.forInsn(insnOffset) : null;
			CommentStyle commentStyle = CommentStyle.valueOf(style.toUpperCase());

			JadxCodeData codeData = (JadxCodeData) jadxArgs.getCodeData();
			if (codeData == null) {
				return JsonOutput.error("NoComments", "No existing comments to update");
			}
			List<ICodeComment> comments = new ArrayList<>(codeData.getComments());

			// Find existing comment by nodeRef and codeRef match
			ICodeComment existing = null;
			for (ICodeComment c : comments) {
				if (c.getNodeRef().equals(nodeRef)) {
					if ((c.getCodeRef() == null && codeRef == null)
							|| (c.getCodeRef() != null && codeRef != null && c.getCodeRef().equals(codeRef))) {
						existing = c;
						break;
					}
				}
			}

			if (existing == null) {
				return JsonOutput.error("CommentNotFound", "No existing comment found for the specified node/code reference");
			}

			comments.remove(existing);
			ICodeComment updated = new JadxCodeComment(nodeRef, codeRef, commentText, commentStyle);
			comments.add(updated);
			Collections.sort(comments);
			codeData.setComments(comments);
			jadxArgs.setCodeData(codeData);
			decompiler.reloadCodeData();

			Map<String, Object> result = new HashMap<>();
			result.put("action", "update");
			result.put("class", className);
			result.put("nodeRef", nodeRef.toString());
			result.put("codeRef", codeRef != null ? codeRef.toString() : null);
			result.put("oldComment", existing.getComment());
			result.put("newComment", commentText);
			result.put("style", commentStyle.name());
			return JsonOutput.ok(result);
		} catch (Exception e) {
			return JsonOutput.error("UpdateFailed", e.getMessage());
		}
	}

	private Object deleteComment(JadxDecompiler decompiler, JavaClass cls) {
		try {
			JadxNodeRef nodeRef = buildNodeRef(decompiler, cls);
			JadxCodeRef codeRef = insnOffset >= 0 ? JadxCodeRef.forInsn(insnOffset) : null;

			JadxCodeData codeData = (JadxCodeData) jadxArgs.getCodeData();
			if (codeData == null) {
				return JsonOutput.error("NoComments", "No existing comments to delete");
			}
			List<ICodeComment> comments = new ArrayList<>(codeData.getComments());

			// Find existing comment by nodeRef and codeRef match
			ICodeComment existing = null;
			for (ICodeComment c : comments) {
				if (c.getNodeRef().equals(nodeRef)) {
					if ((c.getCodeRef() == null && codeRef == null)
							|| (c.getCodeRef() != null && codeRef != null && c.getCodeRef().equals(codeRef))) {
						existing = c;
						break;
					}
				}
			}

			if (existing == null) {
				return JsonOutput.error("CommentNotFound", "No existing comment found for the specified node/code reference");
			}

			comments.remove(existing);
			Collections.sort(comments);
			codeData.setComments(comments);
			jadxArgs.setCodeData(codeData);
			decompiler.reloadCodeData();

			Map<String, Object> result = new HashMap<>();
			result.put("action", "delete");
			result.put("class", className);
			result.put("nodeRef", nodeRef.toString());
			result.put("codeRef", codeRef != null ? codeRef.toString() : null);
			result.put("deletedComment", existing.getComment());
			return JsonOutput.ok(result);
		} catch (Exception e) {
			return JsonOutput.error("DeleteFailed", e.getMessage());
		}
	}

	private JadxNodeRef buildNodeRef(JadxDecompiler decompiler, JavaClass cls) {
		if (methodName != null) {
			JavaMethod mth = findMethod(decompiler, cls, methodName);
			if (mth == null) {
				throw new RuntimeException("Method not found: " + methodName + " in class " + className);
			}
			return JadxNodeRef.forMth(mth);
		} else if (fieldName != null) {
			JavaField fld = findField(decompiler, cls, fieldName);
			if (fld == null) {
				throw new RuntimeException("Field not found: " + fieldName + " in class " + className);
			}
			return JadxNodeRef.forFld(fld);
		} else {
			return JadxNodeRef.forCls(className);
		}
	}

	private JavaMethod findMethod(JadxDecompiler decompiler, JavaClass cls, String mName) {
		for (JavaMethod m : cls.getMethods()) {
			if (m.getName().equals(mName)) {
				return m;
			}
		}
		return null;
	}

	private JavaField findField(JadxDecompiler decompiler, JavaClass cls, String fName) {
		for (JavaField f : cls.getFields()) {
			if (f.getName().equals(fName)) {
				return f;
			}
		}
		return null;
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new HashMap<>();
		args.put("class", className);
		args.put("type", opType);
		if (query != null) {
			args.put("query", query);
		}
		if (commentText != null) {
			args.put("commentText", commentText);
		}
		if (methodName != null) {
			args.put("method", methodName);
		}
		if (fieldName != null) {
			args.put("field", fieldName);
		}
		args.put("style", style);
		args.put("insnOffset", insnOffset);
		return args;
	}
}
