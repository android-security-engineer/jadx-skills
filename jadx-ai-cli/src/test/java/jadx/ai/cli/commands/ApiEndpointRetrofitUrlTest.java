package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the wiring-in of {@link ApiEndpointExtractCommand#RETROFIT_URL} (previously a dead field —
 * declared but never referenced, so {@code @Url} dynamic-URL endpoints were silently missed).
 *
 * <p>A Retrofit method annotated {@code @Url} takes the full URL/path as a runtime argument, so NO
 * literal path appears in code — the {@code @GET("...")}-style extractors all miss it. The
 * {@code URL_LITERAL} fallback only catches literal {@code http(s)://} strings, which a dynamic
 * {@code @Url} endpoint has none. {@code RETROFIT_URL} flags these dynamic-URL endpoints.
 */
class ApiEndpointRetrofitUrlTest {

	private static final java.util.regex.Pattern RETROFIT_URL = ApiEndpointExtractCommand.RETROFIT_URL;

	@Test
	void urlAnnotationFires() {
		assertTrue(RETROFIT_URL.matcher("    @Url").find(),
				"@Url annotation must fire (was a dead field — dynamic-URL endpoints were silently missed)");
	}

	@Test
	void urlAnnotationWithSpaceFires() {
		assertTrue(RETROFIT_URL.matcher("    @Url Call<ResponseBody> fetch(@Url String u);").find(),
				"@Url with trailing content must fire");
	}

	@Test
	void urlAnnotationLowercaseDoesNotFire() {
		assertFalse(RETROFIT_URL.matcher("    @url").find(),
				"@url (lowercase) is not the Retrofit annotation — must NOT fire");
	}

	@Test
	void urlInWordDoesNotFire() {
		// \b after @Url — "UrlFactory" should not match @Url
		assertFalse(RETROFIT_URL.matcher("    @UrlFactory").find(),
				"@UrlFactory must NOT fire the @Url rule (word boundary)");
	}

	@Test
	void getAnnotationDoesNotFireUrlRule() {
		assertFalse(RETROFIT_URL.matcher("    @GET(\"users/{id}\")").find(),
				"@GET must NOT fire the @Url rule");
	}
}
