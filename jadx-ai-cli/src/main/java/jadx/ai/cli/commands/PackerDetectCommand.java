package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.api.ResourceFile;

/**
 * Detects common Android app packers / protectors (360, Tencent Legu, Baidu, Bangcle, ijiami,
 * Naga, etc.) by matching their signature entry classes, stub Application subclasses, native
 * library names, and asset patterns. Absorbs packer detection logic from MobSF and
 * droid-re-chain. Native capability — reads jadx's parsed model.
 */
@Command(name = "packer-detect", description = "Detect app packers and protection wrappers")
public class PackerDetectCommand extends AbstractCommand {

	@Option(names = { "--limit" }, description = "Maximum findings", defaultValue = "20")
	protected int limit = 20;

	/** Packer signature. */
	private static final class PackerSig {
		final String name;
		final String[] classMarkers;
		final String[] resourceMarkers;

		PackerSig(String name, String[] classMarkers, String[] resourceMarkers) {
			this.name = name;
			this.classMarkers = classMarkers;
			this.resourceMarkers = resourceMarkers;
		}
	}

	// Absorbed from MobSF static analysis packer detection + community knowledge
	private static final List<PackerSig> PACKERS = List.of(
			new PackerSig("360 Jiagu (360加固)",
					new String[] { "com.stub.StubApp", "com.qihoo.util.", "com.qihoo360.replugin." },
					new String[] { "libjiagu.so", "libjiagu_32.so", "libjiagu_64.so", "assets/libjiagu" }),
			new PackerSig("Tencent Legu (腾讯乐固)",
					new String[] { "com.tencent.StubShell.TxAppEntry", "com.tencent.buglylegu." },
					new String[] { "libshell-super.2019.so", "libshella-2.10.so", "assets/tosversion" }),
			new PackerSig("Baidu Jiagu (百度加固)",
					new String[] { "com.baidu.protect.", "com.baidu.jiagu." },
					new String[] { "libbaiduprotect.so", "libbaidujg.so", "assets/baidu_dex" }),
			new PackerSig("Bangcle (梆梆加固)",
					new String[] { "com.secshell.shellview.AVShellActivity", "com.secneo.apkwrapper." },
					new String[] { "libsecshell.so", "libsecexe.so", "assets/secdata" }),
			new PackerSig("ijiami (爱加密)",
					new String[] { "com.ijiami.ijiamilock.", "com.ijiami.shell." },
					new String[] { "libijiami.so", "libijiami_sec.so", "assets/ijiami_data" }),
			new PackerSig("Naga (娜迦)",
					new String[] { "com.naga.shell.", "com.naga.gameprotect." },
					new String[] { "libnaga.so", "libnaga_sec.so" }),
			new PackerSig("Tencent YuAnQuan (腾讯御安全)",
					new String[] { "com.tencent.yaokoo.", "com.tencent.bugly." },
					new String[] { "libtencent_sec.so", "assets/tencent_sec" }),
			new PackerSig("Aliprotect (支付宝加固)",
					new String[] { "com.alipay.mobile.quinox.", "com.alipay.protect." },
					new String[] { "libaliprotect.so", "assets/aliprotect" }),
			new PackerSig("Tencent GuJia (腾讯加固)",
					new String[] { "com.tencent.shell.", "com.tencent.SplashActivity" },
					new String[] { "libtencent.so", "libshell.so" }),
			new PackerSig("Netease Jiagu (网易易盾)",
					new String[] { "com.netease.nis.bugrpt.", "com.netease.shell." },
					new String[] { "libnesec.so", "assets/nesec" }),
			new PackerSig("Ali Jiagu (阿里加固)",
					new String[] { "com.taobao.wireless.security.", "com.ali.mobius." },
					new String[] { "libmobius.so", "libsgmain.so", "libsgsecuritybody.so" }),
			new PackerSig("Secneo",
					new String[] { "com.secneo.shell.", "com.secneo.apkwrapper." },
					new String[] { "libsecneo.so", "assets/dex" }),
			new PackerSig("DexGuard / ProGuard (obfuscation, not true packer)",
					new String[] { "DexGuard", "com.dexguard." },
					new String[] { "assets/dexguard" }),
			new PackerSig("APKProtect",
					new String[] { "com.apkprotect.", "com.cn.sto." },
					new String[] { "libapkprotect.so" }),
			new PackerSig("Packer detection heuristics (generic)",
					new String[] { "com.stub.", "com.shell.", "com.wrapper.", "com.loader." },
					new String[] { "assets/dex", "assets/classes.dex" }));

	@Override
	protected void applyArgs(Map<String, Object> args) {
		if (args.containsKey("limit")) {
			this.limit = ((Number) args.get("limit")).intValue();
		}
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		// Gather resource paths.
		List<String> resourceNames = new ArrayList<>();
		for (ResourceFile res : decompiler.getResources()) {
			String n = res.getOriginalName();
			if (n != null) {
				resourceNames.add(n.replace('\\', '/'));
			}
		}

		// Gather class names.
		List<String> classNames = new ArrayList<>();
		for (JavaClass cls : decompiler.getClasses()) {
			classNames.add(cls.getFullName());
		}

		List<Map<String, Object>> findings = new ArrayList<>();
		boolean isPacked = false;
		String primaryPacker = null;

		for (PackerSig sig : PACKERS) {
			if (findings.size() >= limit) {
				break;
			}

			List<String> evidence = new ArrayList<>();
			for (String marker : sig.classMarkers) {
				for (String cn : classNames) {
					if (cn.startsWith(marker) || cn.contains(marker)) {
						evidence.add("class:" + marker);
						break;
					}
				}
			}
			for (String marker : sig.resourceMarkers) {
				for (String rn : resourceNames) {
					if (rn.contains(marker)) {
						evidence.add("resource:" + marker);
						break;
					}
				}
			}

			if (evidence.isEmpty()) {
				continue;
			}

			String confidence;
			if (evidence.size() >= 3) {
				confidence = "high";
			} else if (evidence.size() >= 2) {
				confidence = "medium";
			} else {
				confidence = "low";
			}

			Map<String, Object> f = new LinkedHashMap<>();
			f.put("name", sig.name);
			f.put("confidence", confidence);
			f.put("evidence", evidence);
			findings.add(f);

			// A high/medium confidence finding on a known packer (not the generic heuristic)
			// means the app is likely packed.
			if ((confidence.equals("high") || confidence.equals("medium"))
					&& !sig.name.contains("heuristic")) {
				isPacked = true;
				if (primaryPacker == null) {
					primaryPacker = sig.name;
				}
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("packers", findings);
		data.put("isPacked", isPacked);
		data.put("primaryPacker", primaryPacker);
		return JsonOutput.ok(data);
	}

	@Override
	protected String getDaemonCommandName() {
		return "packer-detect";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new LinkedHashMap<>();
		args.put("limit", limit);
		return args;
	}
}
