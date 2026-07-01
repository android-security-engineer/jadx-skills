package jadx.ai.cli.commands;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.RandomAccessFile;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipFile;

import picocli.CommandLine.Command;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;

/**
 * Extracts the APK signing information — the "who signed this, with what, and which signature
 * scheme" question that anchors trust decisions. Reads the raw APK (no decompilation): the v1
 * JAR signature (PKCS#7 blobs under {@code META-INF/*.RSA|DSA|EC}) via {@link ZipFile}, and the
 * v2/v3 APK Signing Block (the fixed-magic block that precedes the central directory) via a
 * small pure-Java parser. Reports the certificates' subject/issuer, validity window, signature
 * algorithm, and SHA-1 / SHA-256 fingerprints, plus which schemes are present. Absorbs the
 * signing-certificate analysis from {@code droid-re-chain}'s {@code tools_apk.py} in
 * {@code reference/}; reimplemented natively (no apksigner/jarsigner dependency).
 */
@Command(name = "apk-signature",
		description = "Parse APK signing certificates and signature schemes (v1 JAR + v2/v3 signing block)")
public class ApkSignatureCommand extends AbstractCommand {

	// APK Signing Block trailer magic: "APK Sig Block 42"
	private static final byte[] SIG_BLOCK_MAGIC = new byte[] {
			0x41, 0x50, 0x4b, 0x20, 0x53, 0x69, 0x67, 0x20,
			0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x20, 0x34, 0x32
	};
	private static final long APK_SIG_V2_ID = 0x7109871aL;
	private static final long APK_SIG_V3_ID = 0xf05368c0L;
	private static final long APK_SIG_V31_ID = 0x1bc93d8cL;
	private static final long APK_SIG_V4_ID = 0x42726577L; // "Brew"

	@Override
	protected void applyArgs(Map<String, Object> args) {
		// No options.
	}

	@Override
	protected boolean requiresDecompiler() {
		// Only needs the raw APK file, not the decompiled model.
		return false;
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		if (inputFile == null || !inputFile.exists()) {
			return JsonOutput.error("MissingInput",
					"An APK file is required to inspect its signature");
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("file", inputFile.getName());

		List<Map<String, Object>> certs = new ArrayList<>();
		Set<String> schemes = new LinkedHashSet<>();
		List<String> v1SignerFiles = new ArrayList<>();

		// ── v1 (JAR signature): PKCS#7 blobs under META-INF ──
		try (ZipFile zf = new ZipFile(inputFile)) {
			java.util.Enumeration<? extends java.util.zip.ZipEntry> entries = zf.entries();
			while (entries.hasMoreElements()) {
				java.util.zip.ZipEntry e = entries.nextElement();
				String name = e.getName().replace('\\', '/');
				if (name.startsWith("META-INF/")
						&& (name.endsWith(".RSA") || name.endsWith(".DSA") || name.endsWith(".EC"))) {
					v1SignerFiles.add(name);
					schemes.add("v1 (JAR)");
					byte[] pkcs7 = readAll(zf.getInputStream(e));
					Collection<? extends java.security.cert.Certificate> parsed =
							CertificateFactory.getInstance("X.509")
									.generateCertificates(new ByteArrayInputStream(pkcs7));
					for (java.security.cert.Certificate c : parsed) {
						if (c instanceof X509Certificate) {
							certs.add(certToMap((X509Certificate) c, "v1:" + name));
						}
					}
				}
			}
		} catch (Exception ignored) {
			// Not a zip / unreadable — fall through to v2/v3 only.
		}

		// ── v2/v3 (APK Signing Block): locate via central-directory offset ──
		try {
			Map<String, Object> v2v3 = parseSigningBlock(inputFile);
			if (v2v3 != null) {
				@SuppressWarnings("unchecked")
				Set<String> found = (Set<String>) v2v3.get("schemes");
				schemes.addAll(found);
				@SuppressWarnings("unchecked")
				List<Map<String, Object>> v2Certs = (List<Map<String, Object>>) v2v3.get("certificates");
				for (Map<String, Object> cm : v2Certs) {
					if (certs.stream().noneMatch(existing ->
							java.util.Objects.equals(existing.get("sha256"), cm.get("sha256")))) {
						certs.add(cm);
					}
				}
			}
		} catch (Exception ignored) {
			// v2/v3 parsing is best-effort.
		}

		data.put("signatureSchemes", new ArrayList<>(schemes));
		data.put("v1SignerFiles", v1SignerFiles);
		data.put("certificates", certs);
		data.put("certificateCount", certs.size());
		data.put("isSigned", !certs.isEmpty() || !schemes.isEmpty());

		// Roll the per-cert verdicts up to the top level so the trust decision is one field away.
		boolean debugSigned = false;
		boolean weakSigned = false;
		List<String> securityWarnings = new ArrayList<>();
		for (Map<String, Object> c : certs) {
			if (Boolean.TRUE.equals(c.get("debugCertificate"))) {
				debugSigned = true;
			}
			if (Boolean.TRUE.equals(c.get("weakSignatureAlgorithm"))) {
				weakSigned = true;
			}
			Object w = c.get("warnings");
			if (w instanceof List) {
				for (Object item : (List<?>) w) {
					if (!securityWarnings.contains(String.valueOf(item))) {
						securityWarnings.add(String.valueOf(item));
					}
				}
			}
		}
		// v1-only signing is itself a downgrade risk (Janus / no APK-Signing-Block integrity).
		if (!schemes.isEmpty() && schemes.contains("v1 (JAR)") && schemes.size() == 1) {
			securityWarnings.add("only v1 (JAR) signature present — vulnerable to Janus-style tampering; no v2+ block");
		}
		data.put("debugSigned", debugSigned);
		data.put("weakSignatureAlgorithm", weakSigned);
		data.put("securityWarnings", securityWarnings);

		if (certs.isEmpty() && schemes.isEmpty()) {
			data.put("note", "No v1 PKCS#7 signer files and no APK Signing Block found "
					+ "(file may not be an APK, or only target-only signed).");
		}
		return JsonOutput.ok(data);
	}

	private static Map<String, Object> parseSigningBlock(File apk) throws Exception {
		try (RandomAccessFile raf = new RandomAccessFile(apk, "r")) {
			long cdOffset = findCentralDirectoryOffset(raf);
			if (cdOffset < 32) {
				return null;
			}
			// The signing block's trailer (last 24 bytes before the central directory) is
			// [size_copy(8)][magic(16)]. The 16-byte magic sits immediately before the CD.
			raf.seek(cdOffset - 16);
			byte[] magic = new byte[16];
			raf.readFully(magic);
			if (!java.util.Arrays.equals(magic, SIG_BLOCK_MAGIC)) {
				return null; // no signing block
			}
			// size_of_block (excluding its own leading field) is the 8 bytes before magic.
			raf.seek(cdOffset - 24);
			long blockSize = readLeU64(raf);
			// Block layout: [size(8)][ID-value pairs][size_copy(8)][magic(16)].
			// The ID-value region spans [cdOffset - blockSize .. cdOffset - 24).
			if (blockSize <= 24 || cdOffset - blockSize < 0) {
				return null;
			}
			long pos = cdOffset - blockSize;
			long regionEnd = cdOffset - 24;

			Set<String> schemes = new LinkedHashSet<>();
			List<Map<String, Object>> v2Certs = new ArrayList<>();
			while (pos + 12 <= regionEnd) {
				raf.seek(pos);
				long pairLen = readLeU64(raf);
				if (pairLen < 4 || pos + 8 + pairLen > regionEnd) {
					break;
				}
				long id = readLeU32(raf);
				long valueLen = pairLen - 4;
				byte[] value = new byte[(int) Math.min(valueLen, Integer.MAX_VALUE)];
				raf.readFully(value);

				if (id == APK_SIG_V2_ID) {
					schemes.add("v2 (APK)");
					collectV2Certs(value, v2Certs);
				} else if (id == APK_SIG_V3_ID) {
					schemes.add("v3 (APK key rotation)");
					collectV2Certs(value, v2Certs); // v3 shares the v2 signer/cert layout
				} else if (id == APK_SIG_V31_ID) {
					schemes.add("v3.1 (APK lineage)");
					collectV2Certs(value, v2Certs);
				} else if (id == APK_SIG_V4_ID) {
					schemes.add("v4 (incremental)");
				}
				pos += 8 + pairLen;
			}

			Map<String, Object> out = new LinkedHashMap<>();
			out.put("schemes", schemes);
			out.put("certificates", v2Certs);
			return out;
		}
	}

	/**
	 * Parse the certificates out of an APK Signature Scheme v2/v3 signer value.
	 * Layout: signers-seq[len] → first signer[len] → signed-data[len]
	 *         → digests-seq[len] → certificates-seq[len] → (cert[len] bytes each).
	 * All lengths are little-endian uint32.
	 */
	private static void collectV2Certs(byte[] value, List<Map<String, Object>> out) {
		try {
			int[] p = new int[] { 0 };
			int signersLen = readLeU32(value, p);
			int signersEnd = p[0] + signersLen;
			// first signer
			int signerLen = readLeU32(value, p);
			int signerEnd = p[0] + signerLen;
			// signed data
			int signedDataLen = readLeU32(value, p);
			int sdStart = p[0];
			int[] sp = new int[] { sdStart };
			// digests sequence
			int digestsLen = readLeU32(value, sp);
			sp[0] += digestsLen;
			// certificates sequence
			if (sp[0] + 4 > value.length) {
				return;
			}
			int certsSeqLen = readLeU32(value, sp);
			int certsSeqEnd = sp[0] + certsSeqLen;
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			while (sp[0] + 4 <= certsSeqEnd && sp[0] + 4 <= value.length) {
				int certLen = readLeU32(value, sp);
				if (certLen <= 0 || sp[0] + certLen > value.length) {
					break;
				}
				byte[] der = new byte[certLen];
				System.arraycopy(value, sp[0], der, 0, certLen);
				sp[0] += certLen;
				try {
					java.security.cert.Certificate c = cf.generateCertificate(new ByteArrayInputStream(der));
					if (c instanceof X509Certificate) {
						out.add(certToMap((X509Certificate) c, "v2/v3"));
					}
				} catch (Exception ignored) {
					// skip malformed cert
				}
			}
		} catch (Exception ignored) {
			// best-effort; malformed v2 value
		}
	}

	/** Locate the start of the central directory via the End-of-Central-Directory record. */
	private static long findCentralDirectoryOffset(RandomAccessFile raf) throws Exception {
		long fileLen = raf.length();
		int scan = (int) Math.min(fileLen, 65557);
		raf.seek(fileLen - scan);
		byte[] tail = new byte[scan];
		raf.readFully(tail);
		// EOCD signature 0x06054b50 (little-endian: 50 4b 05 06)
		for (int i = tail.length - 22; i >= 0; i--) {
			if (tail[i] == 0x50 && tail[i + 1] == 0x4b && tail[i + 2] == 0x05 && tail[i + 3] == 0x06) {
				long cdOffset = (tail[i + 16] & 0xFFL)
						| ((tail[i + 17] & 0xFFL) << 8)
						| ((tail[i + 18] & 0xFFL) << 16)
						| ((tail[i + 19] & 0xFFL) << 24);
				return cdOffset;
			}
		}
		return -1;
	}

	private static long readLeU64(RandomAccessFile raf) throws Exception {
		byte[] b = new byte[8];
		raf.readFully(b);
		long v = 0;
		for (int i = 7; i >= 0; i--) {
			v = (v << 8) | (b[i] & 0xFFL);
		}
		return v;
	}

	private static long readLeU32(RandomAccessFile raf) throws Exception {
		byte[] b = new byte[4];
		raf.readFully(b);
		return (b[0] & 0xFFL) | ((b[1] & 0xFFL) << 8)
				| ((b[2] & 0xFFL) << 16) | ((b[3] & 0xFFL) << 24);
	}

	private static int readLeU32(byte[] b, int[] p) {
		int v = (b[p[0]] & 0xFF) | ((b[p[0] + 1] & 0xFF) << 8)
				| ((b[p[0] + 2] & 0xFF) << 16) | ((b[p[0] + 3] & 0xFF) << 24);
		p[0] += 4;
		return v;
	}

	private static byte[] readAll(java.io.InputStream is) throws Exception {
		java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
		byte[] buf = new byte[8192];
		int n;
		while ((n = is.read(buf)) > 0) {
			baos.write(buf, 0, n);
		}
		return baos.toByteArray();
	}

	private static Map<String, Object> certToMap(X509Certificate cert, String source) {
		Map<String, Object> m = new LinkedHashMap<>();
		m.put("subject", cert.getSubjectX500Principal().getName());
		m.put("issuer", cert.getIssuerX500Principal().getName());
		m.put("serial", cert.getSerialNumber().toString(16));
		m.put("sigAlgorithm", cert.getSigAlgName());
		m.put("notBefore", format(cert.getNotBefore()));
		m.put("notAfter", format(cert.getNotAfter()));
		boolean expired = new Date().after(cert.getNotAfter());
		m.put("expired", expired);
		try {
			byte[] enc = cert.getEncoded();
			m.put("sha1", hex(MessageDigest.getInstance("SHA-1").digest(enc)));
			m.put("sha256", hex(MessageDigest.getInstance("SHA-256").digest(enc)));
		} catch (Exception ignored) {
			// fingerprint computation best-effort
		}

		// ── Security verdicts on the signing certificate (trust decisions on the data above) ──
		String subject = cert.getSubjectX500Principal().getName();
		String issuer = cert.getIssuerX500Principal().getName();
		boolean selfSigned = subject.equals(issuer); // normal for APK signing certs; reported, not warned
		m.put("selfSigned", selfSigned);

		String keyAlg = cert.getPublicKey().getAlgorithm();
		m.put("keyAlgorithm", keyAlg);
		int keySize = keySizeBits(cert);
		if (keySize > 0) {
			m.put("keySize", keySize);
		}

		// The Android SDK debug keystore signs with a fixed identity: "C=US, O=Android, CN=Android Debug".
		// An app shipped with it is a debug build — not production, and the private key is public.
		boolean debugCert = subject.toLowerCase(java.util.Locale.ROOT).contains("cn=android debug");
		m.put("debugCertificate", debugCert);

		String sigAlg = cert.getSigAlgName();
		String sigUpper = sigAlg == null ? "" : sigAlg.toUpperCase(java.util.Locale.ROOT);
		boolean weakSig = sigUpper.contains("MD5") || sigUpper.contains("SHA1") || sigUpper.contains("MD2");
		m.put("weakSignatureAlgorithm", weakSig);

		List<String> warnings = new ArrayList<>();
		if (debugCert) {
			warnings.add("signed with the Android debug certificate (non-production; private key is public)");
		}
		if (weakSig) {
			warnings.add("weak signature algorithm: " + sigAlg + " (collision-prone)");
		}
		if ("RSA".equalsIgnoreCase(keyAlg) && keySize > 0 && keySize < 2048) {
			warnings.add("undersized RSA key: " + keySize + " bits (< 2048)");
		}
		if (Boolean.TRUE.equals(m.get("expired"))) {
			warnings.add("certificate has expired");
		}
		m.put("warnings", warnings);

		m.put("source", source);
		return m;
	}

	/** Public-key strength in bits: RSA/DSA modulus/prime length or EC field size; 0 if unknown. */
	private static int keySizeBits(X509Certificate cert) {
		try {
			java.security.PublicKey pk = cert.getPublicKey();
			if (pk instanceof RSAPublicKey) {
				return ((RSAPublicKey) pk).getModulus().bitLength();
			}
			if (pk instanceof DSAPublicKey) {
				return ((DSAPublicKey) pk).getParams().getP().bitLength();
			}
			if (pk instanceof ECPublicKey) {
				return ((ECPublicKey) pk).getParams().getCurve().getField().getFieldSize();
			}
		} catch (Exception ignored) {
			// best-effort
		}
		return 0;
	}

	private static String format(Date d) {
		java.text.SimpleDateFormat sdf = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss z");
		return sdf.format(d);
	}

	private static String hex(byte[] bytes) {
		StringBuilder sb = new StringBuilder();
		for (byte b : bytes) {
			sb.append(Character.toUpperCase(Character.forDigit((b >> 4) & 0xF, 16)));
			sb.append(Character.toUpperCase(Character.forDigit(b & 0xF, 16)));
			sb.append(':');
		}
		if (sb.length() > 0) {
			sb.setLength(sb.length() - 1);
		}
		return sb.toString();
	}

	@Override
	protected String getDaemonCommandName() {
		return "apk-signature";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		return new LinkedHashMap<>();
	}
}
