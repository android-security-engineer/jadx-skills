package jadx.ai.cli.index;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Properties;
import java.util.function.Predicate;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.api.JavaField;
import jadx.api.JavaMethod;
import jadx.core.utils.files.FileUtils;

/**
 * A dependency-free, on-disk symbol index for classes, methods, fields and string literals.
 *
 * <p>
 * Rationale: jadx builds its symbol tables entirely in memory ({@code RootNode.clsMap} etc.) and the
 * CLI's {@code search} command scans those in-memory nodes on every call — for {@code string}/{@code code}
 * searches it even decompiles every class into memory each time. This store persists the symbols to a
 * small set of TSV files under {@code <input>.jadx.cache/symbols/} so that repeat searches can be answered
 * by streaming a flat file with constant memory and <em>without loading the decompiler at all</em>.
 * </p>
 *
 * <p>
 * The design mirrors the SQLite symbol index in the {@code jd-mcp-duo} reference project (classes / methods /
 * fields / strings tables keyed by an archive fingerprint), but avoids a JDBC/native dependency: for a CLI
 * whose explicit goal is lower resource usage, a zero-dependency streaming index is a better fit than
 * embedding a database engine, and it works in fully offline builds.
 * </p>
 */
public final class SymbolIndexStore {
	private static final Logger LOG = LoggerFactory.getLogger(SymbolIndexStore.class);

	/** Bump when the on-disk layout changes so stale indexes are rejected. */
	private static final int FORMAT_VERSION = 2;

	private static final String META_FILE = "meta.properties";
	private static final String CLASSES_FILE = "classes.tsv";
	private static final String METHODS_FILE = "methods.tsv";
	private static final String FIELDS_FILE = "fields.tsv";
	private static final String STRINGS_FILE = "strings.tsv";

	private static final Pattern STRING_LITERAL = Pattern.compile("\"(?:\\\\.|[^\"\\\\])*\"");

	public enum Kind {
		CLASS(CLASSES_FILE),
		METHOD(METHODS_FILE),
		FIELD(FIELDS_FILE),
		STRING(STRINGS_FILE);

		private final String file;

		Kind(String file) {
			this.file = file;
		}
	}

	private final Path dir;
	private final File inputFile;

	public SymbolIndexStore(Path cacheDir, File inputFile) {
		this.dir = cacheDir.resolve("symbols");
		this.inputFile = inputFile;
	}

	/** Convenience factory using the shared {@code <input>.jadx.cache/} location. */
	public static SymbolIndexStore forInput(File inputFile) {
		return new SymbolIndexStore(jadx.ai.cli.cache.CacheSupport.resolveCacheDir(inputFile), inputFile);
	}

	public Path getDir() {
		return dir;
	}

	/** Fingerprint of the input file(s); recomputed cheaply without loading the decompiler. */
	public String fingerprint() {
		return FileUtils.buildInputsHash(Collections.singletonList(inputFile.toPath()));
	}

	public boolean exists() {
		return Files.exists(dir.resolve(META_FILE));
	}

	/** True when an index is present, matches the current format version and the input fingerprint. */
	public boolean isValid() {
		try {
			if (!exists()) {
				return false;
			}
			Properties meta = readMeta();
			return String.valueOf(FORMAT_VERSION).equals(meta.getProperty("formatVersion"))
					&& fingerprint().equals(meta.getProperty("fingerprint"));
		} catch (Exception e) {
			return false;
		}
	}

	/**
	 * Whether {@link #build} needs to run before an index-backed query can be served: either no valid
	 * index exists, or strings are requested but the current index was built without them. Used by the
	 * auto-build-on-miss path so the first open populates the index and later opens reuse it.
	 */
	public boolean needsRebuild(boolean withStrings) {
		return !isValid() || (withStrings && !hasStrings());
	}

	public boolean hasStrings() {
		try {
			return exists() && Boolean.parseBoolean(readMeta().getProperty("hasStrings", "false"));
		} catch (Exception e) {
			return false;
		}
	}

	public Properties readMeta() throws IOException {
		Properties props = new Properties();
		try (BufferedReader r = Files.newBufferedReader(dir.resolve(META_FILE), StandardCharsets.UTF_8)) {
			props.load(r);
		}
		return props;
	}

	/**
	 * Build (or rebuild) the index from a loaded decompiler. Classes/methods/fields come from symbol
	 * tables and require no decompilation; strings require decompiling each class and are only produced
	 * when {@code withStrings} is set.
	 */
	public Stats build(JadxDecompiler decompiler, boolean withStrings) throws IOException {
		Files.createDirectories(dir);
		long start = System.currentTimeMillis();
		long classes = 0;
		long methods = 0;
		long fields = 0;
		long strings = 0;
		try (BufferedWriter cw = newWriter(CLASSES_FILE);
				BufferedWriter mw = newWriter(METHODS_FILE);
				BufferedWriter fw = newWriter(FIELDS_FILE);
				BufferedWriter sw = newWriter(STRINGS_FILE)) {
			// Iterate with inners so the class table can answer `list --with-inners` too; the isInner
			// column lets consumers filter back to top-level-only parity (what getClasses() would give).
			// Methods/fields/strings are emitted only for top-level classes to match the existing
			// decompiler-path search behaviour (which scans getClasses() and their own members).
			for (JavaClass cls : decompiler.getClassesWithInners()) {
				boolean inner = cls.isInner();
				String clsFull = cls.getFullName();
				writeRow(cw, clsFull, cls.getName(), nullTo(cls.getPackage()), cls.getRawName(),
						Boolean.toString(inner), accessStr(cls));
				classes++;
				if (inner) {
					continue;
				}
				for (JavaMethod m : cls.getMethods()) {
					writeRow(mw, clsFull, m.getName(), String.valueOf(m.getReturnType()), m.getFullName());
					methods++;
				}
				for (JavaField f : cls.getFields()) {
					writeRow(fw, clsFull, f.getName(), String.valueOf(f.getType()), f.getRawName());
					fields++;
				}
				if (withStrings) {
					strings += indexStrings(sw, cls, clsFull);
				}
			}
		}
		writeMeta(withStrings, classes, methods, fields, strings);
		Stats stats = new Stats(classes, methods, fields, strings, System.currentTimeMillis() - start);
		LOG.info("Symbol index built: {} classes, {} methods, {} fields, {} strings in {}ms at {}",
				classes, methods, fields, strings, stats.buildMillis, dir);
		return stats;
	}

	private long indexStrings(BufferedWriter sw, JavaClass cls, String clsFull) {
		long count = 0;
		String code;
		try {
			code = cls.getCode();
		} catch (Exception e) {
			return 0;
		}
		if (code == null) {
			return 0;
		}
		java.util.regex.Matcher matcher = STRING_LITERAL.matcher(code);
		while (matcher.find()) {
			String literal = matcher.group();
			if (literal.length() > 2) {
				String inner = literal.substring(1, literal.length() - 1);
				try {
					writeRow(sw, clsFull, inner);
					count++;
				} catch (IOException e) {
					break;
				}
			}
		}
		return count;
	}

	// --- query ---------------------------------------------------------------

	/** A matched index row (columns as stored, already unescaped). */
	public static final class Row {
		public final String[] cols;

		Row(String[] cols) {
			this.cols = cols;
		}

		public String col(int i) {
			return i < cols.length ? cols[i] : null;
		}
	}

	/**
	 * Stream the file for {@code kind}, returning up to {@code limit} rows for which {@code rowMatch}
	 * is true. Constant memory: one line held at a time, early exit at the limit.
	 */
	public List<Row> query(Kind kind, Predicate<String[]> rowMatch, int limit) throws IOException {
		List<Row> results = new ArrayList<>();
		Path file = dir.resolve(kind.file);
		if (!Files.exists(file)) {
			return results;
		}
		try (BufferedReader r = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
			String line;
			while ((line = r.readLine()) != null) {
				String[] cols = splitAndUnescape(line);
				if (rowMatch.test(cols)) {
					results.add(new Row(cols));
					if (results.size() >= limit) {
						break;
					}
				}
			}
		}
		return results;
	}

	public void clear() throws IOException {
		if (Files.exists(dir)) {
			try (java.util.stream.Stream<Path> walk = Files.walk(dir)) {
				walk.sorted(Collections.reverseOrder()).forEach(p -> {
					try {
						Files.deleteIfExists(p);
					} catch (IOException ignored) {
						// best-effort cleanup
					}
				});
			}
		}
	}

	// --- io helpers ----------------------------------------------------------

	private BufferedWriter newWriter(String name) throws IOException {
		return Files.newBufferedWriter(dir.resolve(name), StandardCharsets.UTF_8);
	}

	private void writeMeta(boolean withStrings, long classes, long methods, long fields, long strings)
			throws IOException {
		Properties props = new Properties();
		props.setProperty("formatVersion", String.valueOf(FORMAT_VERSION));
		props.setProperty("fingerprint", fingerprint());
		props.setProperty("jadxVersion", JadxDecompiler.getVersion());
		props.setProperty("input", inputFile.getAbsolutePath());
		props.setProperty("hasStrings", String.valueOf(withStrings));
		props.setProperty("classes", String.valueOf(classes));
		props.setProperty("methods", String.valueOf(methods));
		props.setProperty("fields", String.valueOf(fields));
		props.setProperty("strings", String.valueOf(strings));
		props.setProperty("builtAtMs", String.valueOf(System.currentTimeMillis()));
		try (BufferedWriter w = Files.newBufferedWriter(dir.resolve(META_FILE), StandardCharsets.UTF_8)) {
			props.store(w, "jadx-ai symbol index");
		}
	}

	private static void writeRow(BufferedWriter w, String... cols) throws IOException {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < cols.length; i++) {
			if (i > 0) {
				sb.append('\t');
			}
			sb.append(escape(cols[i]));
		}
		sb.append('\n');
		w.write(sb.toString());
	}

	private static String[] splitAndUnescape(String line) {
		String[] parts = line.split("\t", -1);
		for (int i = 0; i < parts.length; i++) {
			parts[i] = unescape(parts[i]);
		}
		return parts;
	}

	private static String nullTo(String v) {
		return v == null ? "" : v;
	}

	private static String accessStr(JavaClass cls) {
		try {
			return cls.getAccessInfo().toString();
		} catch (Exception e) {
			return "";
		}
	}

	private static String escape(String v) {
		if (v == null) {
			return "";
		}
		StringBuilder sb = new StringBuilder(v.length());
		for (int i = 0; i < v.length(); i++) {
			char c = v.charAt(i);
			switch (c) {
				case '\\':
					sb.append("\\\\");
					break;
				case '\t':
					sb.append("\\t");
					break;
				case '\n':
					sb.append("\\n");
					break;
				case '\r':
					sb.append("\\r");
					break;
				default:
					sb.append(c);
			}
		}
		return sb.toString();
	}

	private static String unescape(String v) {
		if (v.indexOf('\\') < 0) {
			return v;
		}
		StringBuilder sb = new StringBuilder(v.length());
		for (int i = 0; i < v.length(); i++) {
			char c = v.charAt(i);
			if (c == '\\' && i + 1 < v.length()) {
				char n = v.charAt(++i);
				switch (n) {
					case 't':
						sb.append('\t');
						break;
					case 'n':
						sb.append('\n');
						break;
					case 'r':
						sb.append('\r');
						break;
					case '\\':
						sb.append('\\');
						break;
					default:
						sb.append(n);
				}
			} else {
				sb.append(c);
			}
		}
		return sb.toString();
	}

	/** Build statistics. */
	public static final class Stats {
		public final long classes;
		public final long methods;
		public final long fields;
		public final long strings;
		public final long buildMillis;

		Stats(long classes, long methods, long fields, long strings, long buildMillis) {
			this.classes = classes;
			this.methods = methods;
			this.fields = fields;
			this.strings = strings;
			this.buildMillis = buildMillis;
		}
	}
}
