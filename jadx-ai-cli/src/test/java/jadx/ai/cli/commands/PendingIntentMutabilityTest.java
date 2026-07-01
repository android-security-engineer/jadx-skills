package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Guards the balanced-paren argument matcher that backs the implicitly-mutable PendingIntent
 * detection in {@link PendingIntentScanCommand}. The flags argument is the last of four and may be
 * a bare {@code 0} or a named constant — a single-line regex cannot reliably read it, so the
 * detector extracts the whole call's argument span. These tests pin the paren matcher's handling of
 * nesting and of parens embedded in string literals (which must not close the call early).
 */
class PendingIntentMutabilityTest {

	@Test
	void matchParenFindsSimpleClose() {
		String s = "getActivity(ctx, 0, intent, 0)";
		int open = s.indexOf('(');
		assertEquals(s.length() - 1, PendingIntentScanCommand.matchParen(s, open));
	}

	@Test
	void matchParenHandlesNestedCalls() {
		//                    the flags arg is itself a call
		String s = "getActivity(ctx, 0, intent, flags(FLAG_IMMUTABLE))";
		int open = s.indexOf('(');
		assertEquals(s.length() - 1, PendingIntentScanCommand.matchParen(s, open),
				"the outer ) must be the match, not the inner one");
	}

	@Test
	void matchParenIgnoresParenInStringLiteral() {
		String s = "getActivity(ctx, 0, intent, \"a)b\", 0)";
		int open = s.indexOf('(');
		assertEquals(s.length() - 1, PendingIntentScanCommand.matchParen(s, open),
				"a ')' inside a string literal must not close the argument list");
	}

	@Test
	void matchParenReturnsMinusOneWhenUnbalanced() {
		String s = "getActivity(ctx, 0, intent, 0";
		int open = s.indexOf('(');
		assertEquals(-1, PendingIntentScanCommand.matchParen(s, open));
	}

	@Test
	void argExtractionSeesLastFlagArgAcrossNesting() {
		// The extracted argument string is what the detector classifies; confirm a nested expression
		// does not truncate it before the flags token.
		String s = "PendingIntent.getActivity(ctx, req(1, 2), intent, PendingIntent.FLAG_UPDATE_CURRENT)";
		int open = s.indexOf('(');
		int close = PendingIntentScanCommand.matchParen(s, open);
		String args = s.substring(open + 1, close);
		// FLAG_UPDATE_CURRENT alone is NOT a mutability flag: neither FLAG_IMMUTABLE nor FLAG_MUTABLE
		// present → the detector must treat this as implicitly mutable.
		org.junit.jupiter.api.Assertions.assertFalse(args.contains("FLAG_IMMUTABLE"));
		org.junit.jupiter.api.Assertions.assertFalse(args.contains("FLAG_MUTABLE"));
		org.junit.jupiter.api.Assertions.assertEquals("ctx, req(1, 2), intent, PendingIntent.FLAG_UPDATE_CURRENT", args);
	}
}
