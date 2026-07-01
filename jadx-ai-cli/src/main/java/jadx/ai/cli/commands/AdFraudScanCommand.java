package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.regex.Pattern;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;

/**
 * Ad-fraud / SDK-abuse scanner — MASVS MSTG-PRIVACY-3 / RESILIENCE-4.
 * Native: reads jadx's parsed model, no external tool.
 *
 * <p>Detects advertising SDK abuse, click-fraud patterns, device fingerprinting
 * for ad targeting, and hidden ad components. Distinct from {@code privacy-scan}
 * (broad PII collection) and {@code debug-artifact-scan} (debug/instrumentation residue).
 *
 * <p>Categories (first-match-wins per line, ONE/class per kind):
 * <ul>
 *   <li>{@code click_fraud} — Ad SDK click/injection patterns (performClick, clickAd,
 *       simulateAdClick, adClickUrl) — generates fake ad revenue</li>
 *   <li>{@code ad_id_tracking} — Advertising ID access (AdvertisingIdClient,
 *       getAdvertisingIdInfo, advertisingId) — persistent cross-app tracking</li>
 *   <li>{@code device_fingerprint_ad} — Device fingerprinting for ad targeting
 *       (AppsFlyer, Adjust, Branch, Kochava, Singular, Tune/Matomy SDK init) —
 *       collects device attributes for attribution/fingerprinting</li>
 *   <li>{@code hidden_ad_component} — Activity/service declared in manifest with
 *       ad-related class names but no visible UI — serves ads in background</li>
 *   <li>{@code ad_sdk} — Known ad SDK presence (AdMob, Facebook Ads, Unity Ads,
 *       AppLovin, IronSource, Vungle, Chartboost, StartApp, InMobi) — inventory</li>
 *   <li>{@code reward_ad_manipulation} — Rewarded ad fraud (onRewardedAdCompleted
 *       without actual ad view, fake reward callbacks) — bypasses ad-gating</li>
 * </ul>
 *
 * Returns {@code {findings:[{kind,severity,className,lineNumber,detail}], count,
 * highSeverityCount, adSdks, hasClickFraud, hasAdTracking, truncated}}.
 */
@Command(name = "ad-fraud-scan",
		description = "Detect ad-fraud / SDK abuse (MASVS MSTG-PRIVACY-3/RESILIENCE-4): click fraud, ad-ID tracking, device fingerprinting for ad targeting, hidden ad components, ad SDK inventory, reward-ad manipulation")
public class AdFraudScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "200")
	protected int limit = 200;

	/** Gate: only scan classes with ad-related markers. */
	private static final Pattern AD_MARKER = Pattern.compile(
			"AdView|AdRequest|AdMob|InterstitialAd|RewardedAd|adView|AdListener|"
					+ "AdvertisingIdClient|advertisingId|performClick|clickAd|"
					+ "AppsFlyerLib|AdjustConfig|Branch|Kochava|Singular|Tune|Matomy|"
					+ "FacebookAd|FBAudienceNetwork|UnityAds|AppLovin|IronSource|"
					+ "Vungle|Chartboost|StartApp|InMobi|onRewardedAdCompleted|"
					+ "MobileAds|AdManager|loadAd|showAd|adUnitId");

	private static final Pattern CLICK_FRAUD = Pattern.compile(
			"performClick\\s*\\(|clickAd\\s*\\(|simulateAdClick|adClickUrl|"
					+ "AdClickHandler|clickAdBanner|autoClickAd|"
					+ "setOnAdClickListener|adClickRedirect");
	private static final Pattern AD_ID = Pattern.compile(
			"AdvertisingIdClient|getAdvertisingIdInfo|advertisingId|"
					+ "AdvertisingIdClient\\$Info|isLimitAdTrackingEnabled");
	private static final Pattern DEVICE_FINGERPRINT = Pattern.compile(
			"AppsFlyerLib|AppsFlyerLib\\.getInstance|AdjustConfig|Adjust\\.onCreate|"
					+ "Branch\\.getInstance|Kochava\\.configure|Singular\\.init|"
					+ "Tune\\.init|MatomySDK|BranchIO|AppsFlyerConversionData");
	private static final Pattern HIDDEN_AD = Pattern.compile(
			"AdActivity|AdService|AdReceiver|AdProvider|AdWidget|"
					+ "BannerActivity|InterstitialActivity|NativeAdActivity");
	private static final Pattern AD_SDK = Pattern.compile(
			"MobileAds\\.initialize|AdRequest\\.Builder|AdView\\(|InterstitialAd\\(|"
					+ "RewardedAd\\(|FBAudienceNetwork|AudienceNetworkAds|"
					+ "UnityAds\\.initialize|UnityAds\\.isReady|"
					+ "AppLovinSdk|AppLovinSdk\\.initializeSdk|"
					+ "IronSource\\.init|IronSource\\.setAdListener|"
					+ "Vungle\\.init|VungleAdConfig|"
					+ "Chartboost\\.startWithAppId|Chartboost\\.cacheInterstitial|"
					+ "StartAppAd|StartAppSDK\\.init|"
					+ "InMobiSdk\\.init|InMobiBanner|InMobiInterstitial");
	private static final Pattern REWARD_MANIPULATION = Pattern.compile(
			"onRewardedAdCompleted|onUserEarnedReward|onRewardVerified|"
					+ "RewardedAdCallback|rewardedAd\\.show|"
					+ "ServerSideVerify|rewardedAdSucceeded|"
					+ "fakeRewardCallback|bypassRewardCheck");

	private static final class Rule {
		final Pattern pattern;
		final String kind;
		final String severity;
		final String detail;
		Rule(Pattern pattern, String kind, String severity, String detail) {
			this.pattern = pattern;
			this.kind = kind;
			this.severity = severity;
			this.detail = detail;
		}
	}

	private static final Rule[] RULES = {
		new Rule(CLICK_FRAUD, "click_fraud", "high",
				"Ad click fraud pattern — programmatic ad clicking generates fake revenue; "
						+ "violates ad network policies and may indicate malware behavior"),
		new Rule(REWARD_MANIPULATION, "reward_ad_manipulation", "high",
				"Rewarded ad manipulation — bypasses ad-gating by faking reward callbacks "
						+ "without actual ad view; enables cheating in reward-based apps"),
		new Rule(AD_ID, "ad_id_tracking", "medium",
				"Advertising ID access — enables persistent cross-app tracking and profiling; "
						+ "users can reset but many don't; consider using app-set ID instead"),
		new Rule(DEVICE_FINGERPRINT, "device_fingerprint_ad", "medium",
				"Attribution/fingerprinting SDK — collects device attributes for ad targeting "
						+ "and attribution; may create device fingerprint for cross-app tracking"),
		new Rule(HIDDEN_AD, "hidden_ad_component", "medium",
				"Hidden ad component — activity/service with ad-related name may serve ads "
						+ "in background without user awareness"),
		new Rule(AD_SDK, "ad_sdk", "info",
				"Ad SDK present — known advertising SDK detected; inventory for privacy review"),
	};

	@Override
	protected void applyArgs(Map<String, Object> args) {
		this.packageFilter = (String) args.get("package");
		if (args.containsKey("limit") && args.get("limit") != null) {
			this.limit = ((Number) args.get("limit")).intValue();
		}
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		List<Map<String, Object>> findings = new ArrayList<>();
		int highSeverityCount = 0;
		TreeSet<String> adSdks = new TreeSet<>();
		boolean hasClickFraud = false;
		boolean hasAdTracking = false;

		for (JavaClass cls : decompiler.getClasses()) {
			if (findings.size() >= limit) {
				break;
			}
			String fullName = cls.getFullName();
			if (packageFilter != null && !fullName.startsWith(packageFilter)) {
				continue;
			}
			String code;
			try {
				code = cls.getCode();
			} catch (Exception e) {
				continue;
			}
			if (code == null || code.isEmpty() || !AD_MARKER.matcher(code).find()) {
				continue;
			}

			// Per-line rule detection (first-match-wins, ONE/class per kind)
			TreeSet<String> reportedKinds = new TreeSet<>();
			String[] lines = code.split("\n", -1);
			for (int i = 0; i < lines.length && findings.size() < limit; i++) {
				String line = lines[i];
				for (Rule r : RULES) {
					if (!reportedKinds.contains(r.kind) && r.pattern.matcher(line).find()) {
						findings.add(finding(r.kind, r.severity, fullName, i + 1, r.detail));
						reportedKinds.add(r.kind);
						if ("high".equals(r.severity)) {
							highSeverityCount++;
						}
						if ("click_fraud".equals(r.kind)) {
							hasClickFraud = true;
						}
						if ("ad_id_tracking".equals(r.kind) || "device_fingerprint_ad".equals(r.kind)) {
							hasAdTracking = true;
						}
						if ("ad_sdk".equals(r.kind)) {
							// Extract SDK name from the line
							if (line.contains("MobileAds") || line.contains("AdRequest") || line.contains("AdView")) {
								adSdks.add("AdMob/Google Ads");
							} else if (line.contains("FBAudienceNetwork") || line.contains("AudienceNetworkAds")) {
								adSdks.add("Facebook Audience Network");
							} else if (line.contains("UnityAds")) {
								adSdks.add("Unity Ads");
							} else if (line.contains("AppLovinSdk")) {
								adSdks.add("AppLovin");
							} else if (line.contains("IronSource")) {
								adSdks.add("IronSource");
							} else if (line.contains("Vungle")) {
								adSdks.add("Vungle");
							} else if (line.contains("Chartboost")) {
								adSdks.add("Chartboost");
							} else if (line.contains("StartApp")) {
								adSdks.add("StartApp");
							} else if (line.contains("InMobi")) {
								adSdks.add("InMobi");
							}
						}
						break;
					}
				}
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("highSeverityCount", highSeverityCount);
		data.put("adSdks", new ArrayList<>(adSdks));
		data.put("hasClickFraud", hasClickFraud);
		data.put("hasAdTracking", hasAdTracking);
		data.put("truncated", findings.size() >= limit);
		return JsonOutput.ok(data);
	}

	private static Map<String, Object> finding(String kind, String severity, String className, int line, String detail) {
		Map<String, Object> f = new LinkedHashMap<>();
		f.put("kind", kind);
		f.put("severity", severity);
		f.put("className", className);
		f.put("lineNumber", line);
		f.put("detail", detail);
		return f;
	}

	@Override
	protected String getDaemonCommandName() {
		return "ad-fraud-scan";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new HashMap<>();
		if (packageFilter != null) {
			args.put("package", packageFilter);
		}
		args.put("limit", limit);
		return args;
	}
}
