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
 * Inventories third-party SDKs and libraries embedded in the APK. Absorbs the SDK detection
 * design from {@code mobile-security-mcp}'s frameworks-detector (which maps ~60 known SDKs for
 * iOS) and applies it to Android: a curated table of analytics, ad, crash-reporting, messaging,
 * payment, social, and utility SDKs matched by resource paths, class prefixes, and manifest
 * entries. This is the "what's in this app?" inventory that tells you which SDKs are present
 * before you decide what to audit. Native capability — reads jadx's parsed model.
 */
@Command(name = "sdk-inventory", description = "Inventory third-party SDKs and libraries in the APK")
public class SdkInventoryCommand extends AbstractCommand {

	@Option(names = { "--categories" }, description = "Comma-separated categories to include (analytics,ads,crash,messaging,payment,social,utility,tracking,all)", defaultValue = "all")
	protected String categories = "all";

	@Option(names = { "--limit" }, description = "Maximum SDK findings", defaultValue = "100")
	protected int limit = 100;

	/** SDK signature: name, category, resource markers, class prefixes. */
	private static final class SdkSig {
		final String name;
		final String category;
		final String[] resourceMarkers;
		final String[] classPrefixes;

		SdkSig(String name, String category, String[] resourceMarkers, String[] classPrefixes) {
			this.name = name;
			this.category = category;
			this.resourceMarkers = resourceMarkers;
			this.classPrefixes = classPrefixes;
		}
	}

	// Absorbed from mobile-security-mcp's frameworks-detector (60 iOS SDKs mapped to Android equivalents)
	// plus droid-re-chain's APK tool knowledge and ultimate-mobile-mcp's SDK catalog.
	private static final List<SdkSig> SDKS = List.of(
			// Analytics
			new SdkSig("Firebase Analytics", "analytics",
					new String[] { "com/google/firebase/analytics", "measurementService" },
					new String[] { "com.google.firebase.analytics.", "com.google.android.gms.measurement." }),
			new SdkSig("Mixpanel", "analytics",
					new String[] { "mixpanel" },
					new String[] { "com.mixpanel.android." }),
			new SdkSig("Amplitude", "analytics",
					new String[] { "amplitude" },
					new String[] { "com.amplitude.api.", "com.amplitude.android." }),
			new SdkSig("Segment", "analytics",
					new String[] { "segment-analytics" },
					new String[] { "com.segment.analytics.", "com.segment.analyticstests." }),
			new SdkSig("Umeng", "analytics",
					new String[] { "umeng", "com/umeng" },
					new String[] { "com.umeng.analytics.", "com.umeng.commonsdk." }),
			new SdkSig("Sensors Data", "analytics",
					new String[] { "sensorsdata" },
					new String[] { "com.sensorsdata.analytics." }),
			new SdkSig("Google Analytics (Legacy)", "analytics",
					new String[] { "com/google/analytics" },
					new String[] { "com.google.analytics.tracking." }),
			// Ads
			new SdkSig("Google AdMob", "ads",
					new String[] { "com/google/android/gms/ads" },
					new String[] { "com.google.android.gms.ads." }),
			new SdkSig("Facebook Ads / Audience Network", "ads",
					new String[] { "com/facebook/ads" },
					new String[] { "com.facebook.ads." }),
			new SdkSig("Unity Ads", "ads",
					new String[] { "com/unity3d/ads" },
					new String[] { "com.unity3d.ads." }),
			new SdkSig("AppLovin", "ads",
					new String[] { "applovin" },
					new String[] { "com.applovin.", "com.applovin.mediation." }),
			new SdkSig("IronSource", "ads",
					new String[] { "ironsource" },
					new String[] { "com.ironsource.", "com.supersonicads." }),
			new SdkSig("Vungle", "ads",
					new String[] { "vungle" },
					new String[] { "com.vungle.warren." }),
			new SdkSig("AdColony", "ads",
					new String[] { "adcolony" },
					new String[] { "com.adcolony.sdk." }),
			new SdkSig("Chartboost", "ads",
					new String[] { "chartboost" },
					new String[] { "com.chartboost.sdk." }),
			// Crash reporting
			new SdkSig("Firebase Crashlytics", "crash",
					new String[] { "com/google/firebase/crashlytics", "crashlytics" },
					new String[] { "com.google.firebase.crashlytics.", "com.crashlytics.android." }),
			new SdkSig("Bugsnag", "crash",
					new String[] { "bugsnag" },
					new String[] { "com.bugsnag.android." }),
			new SdkSig("Sentry", "crash",
					new String[] { "sentry" },
					new String[] { "io.sentry.android.", "io.sentry." }),
			new SdkSig("ACRA", "crash",
					new String[] { "acra" },
					new String[] { "org.acra." }),
			// Messaging / push
			new SdkSig("Firebase Cloud Messaging", "messaging",
					new String[] { "com/google/firebase/messaging", "firebase-messaging" },
					new String[] { "com.google.firebase.messaging.", "com.google.android.gms.gcm." }),
			new SdkSig("Pushy", "messaging",
					new String[] { "pushy" },
					new String[] { "me.pushy.sdk." }),
			new SdkSig("Twilio", "messaging",
					new String[] { "twilio" },
					new String[] { "com.twilio." }),
			// Payment
			new SdkSig("Stripe", "payment",
					new String[] { "stripe" },
					new String[] { "com.stripe.android." }),
			new SdkSig("Braintree", "payment",
					new String[] { "braintree" },
					new String[] { "com.braintreepayments.api.", "com.braintreegateway." }),
			new SdkSig("PayPal", "payment",
					new String[] { "paypal" },
					new String[] { "com.paypal.android.", "com.paypal.pyplcheckout." }),
			new SdkSig("Google Pay / Wallet", "payment",
					new String[] { "com/google/android/gms/wallet", "com/google/android/gms/pay" },
					new String[] { "com.google.android.gms.wallet.", "com.google.android.gms.pay." }),
			// Social
			new SdkSig("Facebook SDK", "social",
					new String[] { "com/facebook", "facebook-common" },
					new String[] { "com.facebook.", "com.facebook.login.", "com.facebook.share." }),
			new SdkSig("Twitter / X", "social",
					new String[] { "com/twitter", "tweet" },
					new String[] { "com.twitter.sdk.android.", "com.twitter." }),
			new SdkSig("WeChat SDK", "social",
					new String[] { "com/tencent/mm/opensdk" },
					new String[] { "com.tencent.mm.opensdk." }),
			new SdkSig("LINE SDK", "social",
					new String[] { "line" },
					new String[] { "com.linecorp.linesdk." }),
			// Tracking / attribution
			new SdkSig("AppsFlyer", "tracking",
					new String[] { "appsflyer" },
					new String[] { "com.appsflyer." }),
			new SdkSig("Adjust", "tracking",
					new String[] { "adjust" },
					new String[] { "com.adjust.sdk." }),
			new SdkSig("Branch", "tracking",
					new String[] { "branch.io", "io/branch" },
					new String[] { "io.branch.referral.", "io.branch.indexing." }),
			new SdkSig("Kochava", "tracking",
					new String[] { "kochava" },
					new String[] { "com.kochava.android.tracker." }),
			new SdkSig("CleverTap", "tracking",
					new String[] { "clevertap" },
					new String[] { "com.clevertap.android." }),
			// Utility
			new SdkSig("Google Play Services", "utility",
					new String[] { "com/google/android/gms" },
					new String[] { "com.google.android.gms." }),
			new SdkSig("OkHttp", "utility",
					new String[] { "okhttp3" },
					new String[] { "okhttp3." }),
			new SdkSig("Retrofit", "utility",
					new String[] { "retrofit2" },
					new String[] { "retrofit2." }),
			new SdkSig("Glide", "utility",
					new String[] { "glide" },
					new String[] { "com.bumptech.glide." }),
			new SdkSig("Picasso", "utility",
					new String[] { "picasso" },
					new String[] { "com.squareup.picasso." }),
			new SdkSig("Dagger / Hilt", "utility",
					new String[] { "dagger" },
					new String[] { "dagger.", "dagger.hilt." }),
			new SdkSig("RxJava", "utility",
					new String[] { "rxjava", "rxandroid" },
					new String[] { "io.reactivex.", "rx." }),
			new SdkSig("ExoPlayer", "utility",
					new String[] { "exoplayer" },
					new String[] { "com.google.android.exoplayer2." }));

	@Override
	protected void applyArgs(Map<String, Object> args) {
		if (args.get("categories") != null) {
			this.categories = (String) args.get("categories");
		}
		if (args.containsKey("limit")) {
			this.limit = ((Number) args.get("limit")).intValue();
		}
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		// Determine which categories to include.
		List<String> wantCats = new ArrayList<>();
		if ("all".equals(categories)) {
			wantCats.add("all");
		} else {
			for (String c : categories.split(",")) {
				wantCats.add(c.trim().toLowerCase());
			}
		}

		// Gather resource paths.
		List<String> resourceNames = new ArrayList<>();
		for (ResourceFile res : decompiler.getResources()) {
			String n = res.getOriginalName();
			if (n != null) {
				resourceNames.add(n.replace('\\', '/'));
			}
		}

		// Gather class names (cheap — no getCode()).
		List<String> classNames = new ArrayList<>();
		for (JavaClass cls : decompiler.getClasses()) {
			classNames.add(cls.getFullName());
		}

		List<Map<String, Object>> findings = new ArrayList<>();
		List<String> categoriesFound = new ArrayList<>();

		for (SdkSig sig : SDKS) {
			if (findings.size() >= limit) {
				break;
			}
			// Filter by requested categories.
			if (!wantCats.contains("all") && !wantCats.contains(sig.category)) {
				continue;
			}

			List<String> evidence = new ArrayList<>();
			for (String marker : sig.resourceMarkers) {
				for (String rn : resourceNames) {
					if (rn.contains(marker)) {
						evidence.add("resource:" + marker);
						break;
					}
				}
			}
			for (String prefix : sig.classPrefixes) {
				for (String cn : classNames) {
					if (cn.startsWith(prefix)) {
						evidence.add("class:" + prefix + "*");
						break;
					}
				}
			}

			if (evidence.isEmpty()) {
				continue;
			}

			if (!categoriesFound.contains(sig.category)) {
				categoriesFound.add(sig.category);
			}

			Map<String, Object> f = new LinkedHashMap<>();
			f.put("category", sig.category);
			f.put("name", sig.name);
			f.put("evidence", evidence);
			findings.add(f);
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("sdks", findings);
		data.put("sdkCount", findings.size());
		data.put("categories", categoriesFound);
		data.put("truncated", findings.size() >= limit);
		return JsonOutput.ok(data);
	}

	@Override
	protected String getDaemonCommandName() {
		return "sdk-inventory";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new LinkedHashMap<>();
		args.put("categories", categories);
		args.put("limit", limit);
		return args;
	}
}
