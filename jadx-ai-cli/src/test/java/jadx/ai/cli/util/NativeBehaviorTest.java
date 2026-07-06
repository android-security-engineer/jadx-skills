package jadx.ai.cli.util;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the capa-style native behavior classifier: imported symbols and embedded strings map to
 * the right capability tags with concrete evidence, and benign inputs stay quiet.
 */
class NativeBehaviorTest {

	private static boolean has(List<Map<String, Object>> tags, String behavior) {
		return tags.stream().anyMatch(t -> behavior.equals(t.get("behavior")));
	}

	@Test
	void flagsAntiDebugAndExecFromImports() {
		Set<String> imports = new LinkedHashSet<>();
		imports.add("ptrace");
		imports.add("execve");
		imports.add("malloc"); // benign, must not create a tag
		List<Map<String, Object>> tags = NativeBehavior.classify(imports, "");
		assertTrue(has(tags, "anti-debug"), "ptrace => anti-debug");
		assertTrue(has(tags, "process-execution"), "execve => process-execution");
		assertFalse(has(tags, "networking"), "no socket import => no networking tag");
	}

	@Test
	void flagsDynamicLoadingAndRecordsEvidence() {
		Set<String> imports = new LinkedHashSet<>();
		imports.add("dlopen");
		imports.add("dlsym");
		List<Map<String, Object>> tags = NativeBehavior.classify(imports, "");
		Map<String, Object> dl = tags.stream()
				.filter(t -> "dynamic-code-loading".equals(t.get("behavior"))).findFirst().orElseThrow();
		@SuppressWarnings("unchecked")
		List<String> evidence = (List<String>) dl.get("evidence");
		assertTrue(evidence.contains("dlopen") && evidence.contains("dlsym"), "evidence must list the hits");
	}

	@Test
	void flagsRootAndDebuggerDetectionFromStrings() {
		String strings = "harmless\n/system/bin/su\nchecking TracerPid now\nfrida-server";
		List<Map<String, Object>> tags = NativeBehavior.classify(new LinkedHashSet<>(), strings);
		assertTrue(has(tags, "root-detection"), "/system/bin/su => root-detection");
		assertTrue(has(tags, "debugger-detection"), "TracerPid => debugger-detection");
		assertTrue(has(tags, "tamper-detection"), "frida => tamper-detection");
	}

	@Test
	void benignInputProducesNoTags() {
		Set<String> imports = new LinkedHashSet<>();
		imports.add("malloc");
		imports.add("free");
		imports.add("memcpy");
		assertEquals(0, NativeBehavior.classify(imports, "just some ui strings").size(),
				"benign lib must produce no behavior tags");
	}
}
