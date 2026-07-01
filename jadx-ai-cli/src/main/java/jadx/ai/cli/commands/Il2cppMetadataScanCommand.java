package jadx.ai.cli.commands;

import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.ResourceFile;

/**
 * Scans Unity IL2CPP {@code global-metadata.dat} embedded in the APK and
 * extracts the C# symbol table: class names, method names, field names,
 * and namespaces. Absorbs the metadata parsing design from
 * {@code re-il2cpp}'s {@code metadata.py} (which recovers the readable
 * C# symbol table from the unprotected global-metadata.dat file) and
 * reimplements it natively in pure Java over jadx's resource API.
 *
 * <p>The global-metadata.dat format is documented by Il2CppDumper: a header
 * with a magic number (0xFAB11BAF), version, and string table offset/size,
 * followed by null-terminated UTF-8 strings packed contiguously. We scan the
 * string table for C# identifier-shaped strings to recover type/method/field
 * names without requiring Il2CppDumper.</p>
 */
@Command(name = "il2cpp-metadata-scan", description = "Scan Unity IL2CPP global-metadata.dat and extract C# class/method/field names")
public class Il2cppMetadataScanCommand extends AbstractCommand {

	@Option(names = { "--limit" }, description = "Maximum names to return per category", defaultValue = "500")
	protected int limit = 500;

	private static final int IL2CPP_MAGIC = 0xFAB11BAF;

	@Override
	protected void applyArgs(Map<String, Object> args) {
		if (args.containsKey("limit")) {
			this.limit = ((Number) args.get("limit")).intValue();
		}
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		// Find global-metadata.dat in resources
		byte[] metadataBytes = null;
		for (ResourceFile res : decompiler.getResources()) {
			String name = res.getOriginalName();
			if (name != null && name.replace('\\', '/').endsWith("global-metadata.dat")) {
				try {
					String text = res.loadContent().getText().toString();
					metadataBytes = text.getBytes("ISO-8859-1");
				} catch (Exception e) {
					// Try alternative: load as raw bytes not available in this API
				}
				break;
			}
		}

		if (metadataBytes == null) {
			Map<String, Object> data = new LinkedHashMap<>();
			data.put("found", false);
			data.put("message", "global-metadata.dat not found in APK — not a Unity IL2CPP app");
			return JsonOutput.ok(data);
		}

		// Parse the header
		ByteBuffer buf = ByteBuffer.wrap(metadataBytes).order(ByteOrder.LITTLE_ENDIAN);
		int magic = buf.getInt();
		if (magic != IL2CPP_MAGIC) {
			Map<String, Object> data = new LinkedHashMap<>();
			data.put("found", true);
			data.put("error", "Invalid IL2CPP magic number: 0x" + Integer.toHexString(magic));
			return JsonOutput.ok(data);
		}

		int version = buf.getInt();
		// Skip to string table offset/size
		// Header layout (version 24+): magic(4) + version(4) + ... stringLiteralOffset(4) + stringLiteralSize(4) + ...
		// The exact offset depends on version; for v24-v29, stringLiteralOffset is at byte 36
		int stringOffset = 0;
		int stringSize = 0;
		try {
			if (version >= 24 && version <= 31) {
				// stringLiteralOffset at offset 36, stringLiteralSize at offset 40
				buf.position(36);
				stringOffset = buf.getInt();
				stringSize = buf.getInt();
			} else if (version >= 19) {
				// Older versions: stringLiteralOffset at offset 32
				buf.position(32);
				stringOffset = buf.getInt();
				stringSize = buf.getInt();
			}
		} catch (Exception e) {
			// Fallback: scan entire file for strings
			stringOffset = 0;
			stringSize = metadataBytes.length;
		}

		// Extract strings from the string table
		List<String> namespaces = new ArrayList<>();
		List<String> classNames = new ArrayList<>();
		List<String> methodNames = new ArrayList<>();
		List<String> fieldNames = new ArrayList<>();

		if (stringOffset > 0 && stringSize > 0 && stringOffset + stringSize <= metadataBytes.length) {
			scanStringTable(metadataBytes, stringOffset, stringSize, namespaces, classNames, methodNames, fieldNames);
		}

		// Also scan entire metadata for additional strings (the type/method name arrays)
		if (classNames.size() < 10) {
			scanStringTable(metadataBytes, 0, metadataBytes.length, namespaces, classNames, methodNames, fieldNames);
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("found", true);
		data.put("version", version);
		data.put("stringTableOffset", stringOffset);
		data.put("stringTableSize", stringSize);
		data.put("namespaces", namespaces);
		data.put("classNames", classNames);
		data.put("methodNames", methodNames);
		data.put("fieldNames", fieldNames);
		data.put("stats", Map.of(
				"namespaceCount", namespaces.size(),
				"classCount", classNames.size(),
				"methodCount", methodNames.size(),
				"fieldCount", fieldNames.size()));
		return JsonOutput.ok(data);
	}

	/**
	 * Scan the string table for C# identifier-shaped strings.
	 * Classifies strings into namespaces (dotted, no parens), class names
	 * (Capitalized, may have generics), method names (with parens or lowercase start),
	 * and field names (camelCase or _prefixed).
	 */
	private void scanStringTable(byte[] data, int offset, int size,
			List<String> namespaces, List<String> classNames,
			List<String> methodNames, List<String> fieldNames) {
		int end = Math.min(offset + size, data.length);
		StringBuilder sb = new StringBuilder();
		for (int i = offset; i < end; i++) {
			byte b = data[i];
			if (b == 0) {
				if (sb.length() >= 2 && sb.length() <= 512) {
					String s = sb.toString();
					classifyString(s, namespaces, classNames, methodNames, fieldNames);
				}
				sb.setLength(0);
			} else if (b >= 0x20 && b < 0x7F) {
				sb.append((char) b);
			} else {
				// Non-ASCII byte — skip this string
				sb.setLength(0);
				// Advance to next null terminator
				while (i < end && data[i] != 0) i++;
			}
		}
	}

	private void classifyString(String s, List<String> namespaces,
			List<String> classNames, List<String> methodNames,
			List<String> fieldNames) {
		// Skip obviously non-C# strings
		if (s.length() < 2 || s.length() > 400) return;
		// Skip strings that are clearly not identifiers (contain too many special chars)
		long specialChars = s.chars().filter(c -> !Character.isJavaIdentifierPart((char) c)).count();
		if (specialChars > s.length() * 0.3) return;

		boolean hasDot = s.indexOf('.') >= 0;
		boolean hasParen = s.indexOf('(') >= 0;
		boolean hasSlash = s.indexOf('/') >= 0;
		char first = s.charAt(0);

		if (hasParen) {
			// Method-like: contains parentheses
			if (methodNames.size() < limit && !methodNames.contains(s)) {
				methodNames.add(s);
			}
		} else if (hasDot && !hasSlash && Character.isUpperCase(first)) {
			// Namespace-like: dotted, starts with uppercase
			if (namespaces.size() < limit && !namespaces.contains(s)) {
				namespaces.add(s);
			}
		} else if (Character.isUpperCase(first) && !hasDot && !hasSlash) {
			// Class-like: starts with uppercase, single word
			if (classNames.size() < limit && !classNames.contains(s)) {
				classNames.add(s);
			}
		} else if (Character.isLowerCase(first) || first == '_') {
			// Field/method-like: starts with lowercase or underscore
			if (s.length() <= 80 && fieldNames.size() < limit && !fieldNames.contains(s)) {
				fieldNames.add(s);
			}
		}
	}

	@Override
	protected String getDaemonCommandName() {
		return "il2cpp-metadata-scan";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new LinkedHashMap<>();
		args.put("limit", limit);
		return args;
	}
}
