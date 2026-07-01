package jadx.ai.cli.commands;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.ai.cli.util.SecretPatterns;
import jadx.api.JadxDecompiler;
import jadx.api.ResourceFile;
import jadx.api.ResourcesLoader;

/**
 * Analyzes a React Native APK by reading the JavaScript bundle
 * ({@code assets/index.android.bundle}) as raw bytes and determining whether it ships as
 * <em>Hermes bytecode</em> or <em>plaintext JavaScript</em> — the single fact that decides how the
 * app is reverse-engineered. Absorbs the design idea from {@code hermes-dec}/{@code hbctool} (which
 * parse the Hermes Bytecode File header to recover the bytecode version before disassembly) and
 * reimplements the header parse natively in pure Java over jadx's resource API.
 *
 * <p>Why this is not covered by {@code framework-detect}, {@code secrets-scan} or
 * {@code ioc-extract}: those only match resource <em>names</em> or scan decompiled <em>Java</em>
 * classes. In a React Native app the Java/Kotlin layer is a thin shell — the entire application
 * logic, and almost every hardcoded secret and endpoint, lives inside {@code index.android.bundle},
 * which none of those commands ever open. This command reads that file's bytes and, when the bundle
 * is plaintext JS (or after string-extracting Hermes bytecode), runs the shared
 * {@link SecretPatterns} library and a cleartext-URL scan over its contents.</p>
 *
 * <p>Hermes Bytecode File header (little-endian), from Hermes {@code BytecodeFileFormat.h}:
 * {@code uint64 magic = 0x1F1903C103BC1FC6} at offset 0, {@code uint32 version} at offset 8,
 * {@code uint8 sourceHash[20]} at offset 12, {@code uint32 fileLength} at offset 32,
 * {@code uint32 functionCount} at offset 40, {@code uint32 stringCount} at offset 52. The bytecode
 * version dictates which {@code hbctool}/{@code hermes-dec} release can disassemble the file, so it
 * is reported as the key downstream-tooling signal.</p>
 */
@Command(name = "react-native-analysis",
		description = "Analyze a React Native APK: detect Hermes bytecode vs plaintext JS bundle, read bytecode version, scan the bundle for secrets/URLs")
public class ReactNativeAnalysisCommand extends AbstractCommand {

	@Option(names = { "--min-entropy" }, description = "Min Shannon entropy for generic secret detection in the bundle", defaultValue = "4.0")
	protected double minEntropy = 4.0;

	@Option(names = { "--limit" }, description = "Maximum secrets/URLs to return", defaultValue = "200")
	protected int limit = 200;

	/** Hermes Bytecode File magic (uint64, little-endian on disk). */
	static final long HERMES_MAGIC = 0x1F1903C103BC1FC6L;

	/** Cap the raw bundle read (96 MiB — large RN bundles, still bounded so a crafted file can't OOM). */
	private static final long MAX_BUNDLE_BYTES = 100663296L;

	/**
	 * A URL inside the bundle — an RN app's network calls often hide here. The body stops at the first
	 * character that would end a URL embedded in (minified) JS or a string literal — quotes, brackets,
	 * whitespace, backslash — so a run of code after the URL isn't swallowed into one giant match.
	 */
	private static final Pattern HTTP_URL = Pattern.compile(
			"\\bhttps?://[^\\s\"'`\\\\<>)}\\];,]+");

	@Override
	protected void applyArgs(Map<String, Object> args) {
		if (args.containsKey("min_entropy") && args.get("min_entropy") != null) {
			this.minEntropy = ((Number) args.get("min_entropy")).doubleValue();
		}
		if (args.containsKey("limit") && args.get("limit") != null) {
			this.limit = ((Number) args.get("limit")).intValue();
		}
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		ResourceFile bundleRes = null;
		boolean hasHermesLib = false;
		boolean hasJscLib = false;
		boolean hasReactNativeLib = false;
		List<String> bundlePaths = new ArrayList<>();

		for (ResourceFile res : decompiler.getResources()) {
			String name = res.getOriginalName();
			if (name == null) {
				continue;
			}
			String norm = name.replace('\\', '/');
			if (norm.endsWith("index.android.bundle") || norm.endsWith(".jsbundle")) {
				bundlePaths.add(norm);
				// Prefer a real ARSC/asset resource we can decode as a stream.
				if (bundleRes == null) {
					bundleRes = res;
				}
			}
			if (norm.contains("libhermes.so")) {
				hasHermesLib = true;
			}
			if (norm.contains("libjsc.so")) {
				hasJscLib = true;
			}
			if (norm.contains("libreactnativejni.so") || norm.contains("libreact")) {
				hasReactNativeLib = true;
			}
		}

		boolean isReactNative = !bundlePaths.isEmpty() || hasHermesLib || hasJscLib || hasReactNativeLib;

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("isReactNative", isReactNative);
		data.put("hasHermesLib", hasHermesLib);
		data.put("hasJscLib", hasJscLib);
		data.put("hasReactNativeLib", hasReactNativeLib);
		data.put("bundlePaths", bundlePaths);

		if (bundleRes == null) {
			data.put("bundleFound", false);
			if (isReactNative) {
				data.put("note", "React Native native libs present but no index.android.bundle resource could be read");
			}
			return JsonOutput.ok(data);
		}

		byte[] bytes;
		try {
			bytes = ResourcesLoader.decodeStream(bundleRes,
					(size, is) -> is.readNBytes((int) Math.min(MAX_BUNDLE_BYTES, Integer.MAX_VALUE)));
		} catch (Exception e) {
			data.put("bundleFound", true);
			data.put("error", "could not read bundle bytes: " + e.getMessage());
			return JsonOutput.ok(data);
		}
		if (bytes == null || bytes.length < 16) {
			data.put("bundleFound", true);
			data.put("error", "bundle too small to analyze");
			return JsonOutput.ok(data);
		}

		data.put("bundleFound", true);
		data.put("bundleBytes", bytes.length);

		boolean hermes = isHermesBytecode(bytes);
		data.put("hermesBytecode", hermes);

		// The text we scan for secrets/URLs: plaintext JS is scanned whole; Hermes bytecode is
		// string-extracted first (identifiers, string-table entries, embedded URLs survive as ASCII).
		String scanText;
		if (hermes) {
			long version = hermesBytecodeVersion(bytes);
			data.put("hermesBytecodeVersion", version);
			data.put("hermesFunctionCount", readU32(bytes, 40));
			data.put("hermesStringCount", readU32(bytes, 52));
			data.put("reversingHint", "Hermes bytecode — disassemble with hermes-dec/hbctool built for bytecode version " + version);
			scanText = asciiStrings(bytes, 5);
		} else {
			// A plaintext JS bundle means the entire app source is directly readable — trivial to
			// reverse and to lift secrets from. That is itself a security-relevant finding.
			data.put("jsBundlePlaintext", true);
			data.put("reversingHint", "Plaintext JS bundle — source is directly readable; deobfuscate with a JS beautifier");
			scanText = new String(bytes, java.nio.charset.StandardCharsets.UTF_8);
		}

		// Secrets in the bundle — the shared curated pattern library + entropy filter, over content
		// that secrets-scan (Java-only) never sees.
		List<Map<String, Object>> secrets = new ArrayList<>();
		SecretPatterns.scanText(scanText, "index.android.bundle", "js-bundle", minEntropy, limit, secrets);
		data.put("secrets", secrets);
		data.put("secretCount", secrets.size());

		// Cleartext + all URLs embedded in the bundle (deduped, capped).
		List<String> urls = extractUrls(scanText, limit);
		long cleartext = urls.stream().filter(u -> u.startsWith("http://")).count();
		data.put("urls", urls);
		data.put("urlCount", urls.size());
		data.put("cleartextUrlCount", cleartext);

		List<String> notes = new ArrayList<>();
		if (!hermes) {
			notes.add("Bundle ships as plaintext JavaScript — all app logic and any embedded secrets are directly readable");
		}
		if (cleartext > 0) {
			notes.add(cleartext + " cleartext http:// URL(s) embedded in the JS bundle (MITM exposure)");
		}
		if (!secrets.isEmpty()) {
			notes.add(secrets.size() + " candidate secret(s) found inside the bundle — not visible to Java-only secret scanners");
		}
		if (!notes.isEmpty()) {
			data.put("notes", notes);
		}
		return JsonOutput.ok(data);
	}

	/** True if the first 8 bytes are the Hermes Bytecode File magic (little-endian on disk). */
	static boolean isHermesBytecode(byte[] data) {
		if (data == null || data.length < 8) {
			return false;
		}
		long magic = ByteBuffer.wrap(data, 0, 8).order(ByteOrder.LITTLE_ENDIAN).getLong();
		return magic == HERMES_MAGIC;
	}

	/** Hermes bytecode version: {@code uint32} at offset 8. Returns -1 if the buffer is too short. */
	static long hermesBytecodeVersion(byte[] data) {
		return readU32(data, 8);
	}

	/** Read an unsigned 32-bit little-endian int at {@code off}; -1 if out of range. */
	private static long readU32(byte[] data, int off) {
		if (data == null || off < 0 || off + 4 > data.length) {
			return -1;
		}
		return ByteBuffer.wrap(data, off, 4).order(ByteOrder.LITTLE_ENDIAN).getInt() & 0xFFFFFFFFL;
	}

	/** Distinct URLs (http/https) in scan order, capped at {@code max}. */
	static List<String> extractUrls(String text, int max) {
		List<String> out = new ArrayList<>();
		Matcher m = HTTP_URL.matcher(text);
		while (m.find() && out.size() < max) {
			String u = m.group();
			if (!out.contains(u)) {
				out.add(u);
			}
		}
		return out;
	}

	/** Extract printable-ASCII runs of at least {@code minLen} chars, newline-separated. */
	static String asciiStrings(byte[] data, int minLen) {
		StringBuilder sb = new StringBuilder();
		StringBuilder cur = new StringBuilder();
		for (byte b : data) {
			if (b >= 32 && b < 127) {
				cur.append((char) b);
			} else {
				if (cur.length() >= minLen) {
					sb.append(cur).append('\n');
				}
				cur.setLength(0);
			}
		}
		if (cur.length() >= minLen) {
			sb.append(cur);
		}
		return sb.toString();
	}

	@Override
	protected String getDaemonCommandName() {
		return "react-native-analysis";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new LinkedHashMap<>();
		args.put("min_entropy", minEntropy);
		args.put("limit", limit);
		return args;
	}
}
