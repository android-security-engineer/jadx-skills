package jadx.ai.cli.commands;

import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the {@code deeplink_auth_decision} detection in {@link InsecureDeeplinkHandlerScanCommand}.
 *
 * <p>The old same-line AND ({@code getQueryParameter.*(?:isAdmin|role|auth|token|session)}) only fired
 * when the URI-parameter extraction and the auth check shared a single line. The common jadx-decompiled
 * form is cross-line: the keyword lives on the <b>decision</b> line, not the extraction line —
 *
 * <pre>
 * String role = uri.getQueryParameter("role");  // source line — no auth keyword beyond the literal
 * if (role.equals("admin")) { grantAdmin(); }   // sink line — the actual auth decision
 * </pre>
 *
 * The detector now pairs a class-scope deep-link source ({@link #DEEPLINK_SOURCE}) with a line-scope
 * auth-decision sink ({@link #AUTH_DECISION_SINK}) via {@link #deeplinkAuthDecisionSignal}, mirroring
 * the deeplink_path_traversal / sql / webview / class-load cross-line fixes.
 */
class InsecureDeeplinkHandlerAuthDecisionTest {

	private static final Pattern SOURCE = InsecureDeeplinkHandlerScanCommand.DEEPLINK_SOURCE;
	private static final Pattern SINK = InsecureDeeplinkHandlerScanCommand.AUTH_DECISION_SINK;

	private static boolean injectable(String code) {
		boolean classHasSource = SOURCE.matcher(code).find();
		for (String line : code.split("\n", -1)) {
			if (InsecureDeeplinkHandlerScanCommand.deeplinkAuthDecisionSignal(classHasSource, line)) {
				return true;
			}
		}
		return false;
	}

	@Test
	void roleParamEqualsAdminAcrossLinesFires() {
		assertTrue(injectable("String role = uri.getQueryParameter(\"role\");\n"
				+ "if (role.equals(\"admin\")) { grantAdmin(); }"),
				"deep-link role param flowing into a role.equals(\"admin\") decision on another line must fire");
	}

	@Test
	void tokenParamVerifyTokenAcrossLinesFires() {
		assertTrue(injectable("String t = getIntent().getData().getQueryParameter(\"t\");\n"
				+ "verifyToken(t);"),
				"deep-link token param flowing into verifyToken() on another line must fire");
	}

	@Test
	void grantAdminMethodCallOnSinkLineFires() {
		assertTrue(injectable("Uri data = getIntent().getData();\n"
				+ "String a = data.getQueryParameter(\"a\");\n"
				+ "if (\"1\".equals(a)) { grantAdmin(u); }"),
				"a deep-link param driving a grantAdmin() call must fire");
	}

	@Test
	void isAuthenticatedCheckAcrossLinesFires() {
		assertTrue(injectable("String v = uri.getQueryParameter(\"v\");\n"
				+ "if (isAuthenticated(v)) { enter(); }"),
				"a deep-link param driving an isAuthenticated() check must fire");
	}

	@Test
	void authSinkWithoutDeepLinkSourceDoesNotFire() {
		assertFalse(injectable("String role = localConfig.getRole();\n"
				+ "if (role.equals(\"admin\")) { grantAdmin(); }"),
				"an auth decision with no deep-link source in the class must NOT fire — no untrusted input");
	}

	@Test
	void deepLinkSourceWithoutAuthSinkDoesNotFire() {
		assertFalse(injectable("String q = uri.getQueryParameter(\"q\");\n"
				+ "textView.setText(q);"),
				"a deep-link source that never reaches an auth-decision sink must NOT fire");
	}
}
