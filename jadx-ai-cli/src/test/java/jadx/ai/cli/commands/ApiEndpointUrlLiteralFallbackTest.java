package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the URL-literal fallback deepening of {@link ApiEndpointExtractCommand#URL_LITERAL}.
 *
 * <p>The structured extractors ({@code .url("...")}, Retrofit {@code baseUrl("...")}) require the URL
 * as a direct string-literal argument. They MISS two real-world forms jadx emits:
 * <ul>
 *   <li><b>String.format assembly</b> — {@code String.format("%s/api", "https://host")} decompiles with
 *       the URL as a format ARGUMENT, not the {@code .url(} argument; {@code OKHTTP_URL} (which expects
 *       {@code .url("...")}) does not fire. {@code URL_LITERAL} harvests the {@code https://host}
 *       literal from the format args.</li>
 *   <li><b>Resource-indirect</b> — {@code getString(R.string.base_url)} has no URL literal in code at
 *       all; the URL lives in strings.xml/ARSC. (Covered by the resource-scan path in execute, not this
 *       Pattern test — the Pattern test guards the code-side fallback.)</li>
 * </ul>
 * Verified against real javac&#8594;d8&#8594;jadx output.
 */
class ApiEndpointUrlLiteralFallbackTest {

	private static final java.util.regex.Pattern URL_LITERAL = ApiEndpointExtractCommand.URL_LITERAL;

	@Test
	void urlStringFormatArgFires() {
		// The real jadx-decompiled form: String.format("%s/api/v1/login", "https://api.example.com")
		String line = "System.out.println(String.format(\"%s/api/v1/login\", \"https://api.example.com\"));";
		assertTrue(URL_LITERAL.matcher(line).find(),
				"a URL assembled via String.format (URL in the format args) must be harvested by the fallback");
	}

	@Test
	void directUrlLiteralFires() {
		assertTrue(URL_LITERAL.matcher("String u = \"https://api.example.com/users\";").find(),
				"a direct URL literal must fire");
	}

	@Test
	void httpUrlFires() {
		assertTrue(URL_LITERAL.matcher("loadUrl(\"http://example.com\");").find(),
				"an http:// URL must fire");
	}

	@Test
	void urlWithQueryAndPathFires() {
		assertTrue(URL_LITERAL.matcher("\"https://api.example.com/v1/users?id=42&format=json\"").find(),
				"a URL with path and query must fire as one match");
	}

	@Test
	void nonUrlDoesNotFire() {
		assertFalse(URL_LITERAL.matcher("String path = \"/api/v1/login\";").find(),
				"a bare path (no scheme) must NOT fire");
	}

	@Test
	void formatStringPlaceholderDoesNotFire() {
		// The %s/api/v1/login placeholder itself is not a URL
		assertFalse(URL_LITERAL.matcher("\"%s/api/v1/login\"").find(),
				"a %s placeholder string is not a URL and must NOT fire");
	}
}
