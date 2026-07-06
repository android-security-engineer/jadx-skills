package jadx.ai.cli.commands;

import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the expanded {@code untrusted_ipc_object} rule in {@link SerializationScanCommand#IPC_OBJECT_SOURCE}.
 *
 * <p>The old rule matched only {@code getSerializableExtra(} / {@code getParcelableExtra(} — the
 * single-value Bundle getters. But an attacker can smuggle a forged {@link android.os.Parcelable}
 * just as well through the array/list variants ({@code getParcelableArrayExtra},
 * {@code getParcelableArrayListExtra}, {@code getSerializableArrayListExtra}) and through the
 * API 33+ two-arg overload {@code getSerializable(name, Class.class)}; all of these hand back an
 * attacker-forgeable object that the victim typically casts to an app type. The single-value rule
 * silently missed every array/list form.
 */
class SerializationIpcObjectSourceTest {

	private static final Pattern RULE = Pattern.compile(SerializationScanCommand.IPC_OBJECT_SOURCE.pattern());

	private static boolean fires(String line) {
		return RULE.matcher(line).find();
	}

	@Test
	void singleValueGettersStillFire() {
		assertTrue(fires("Serializable s = intent.getSerializableExtra(\"key\");"),
				"getSerializableExtra must still fire (regression guard)");
		assertTrue(fires("Parcelable p = intent.getParcelableExtra(\"key\");"),
				"getParcelableExtra must still fire (regression guard)");
	}

	@Test
	void parcelableArrayExtraFires() {
		assertTrue(fires("Parcelable[] arr = intent.getParcelableArrayExtra(\"items\");"),
				"getParcelableArrayExtra smuggles an array of forged Parcelable — must fire");
	}

	@Test
	void parcelableArrayListExtraFires() {
		assertTrue(fires("ArrayList<Parcelable> list = intent.getParcelableArrayListExtra(\"items\");"),
				"getParcelableArrayListExtra smuggles a list of forged Parcelable — must fire");
	}

	@Test
	void serializableArrayListExtraFires() {
		assertTrue(fires("ArrayList<? extends Serializable> list = intent.getSerializableArrayListExtra(\"items\");"),
				"getSerializableArrayListExtra is an equivalent forged-object entry — must fire");
	}

	@Test
	void api33TwoArgGetSerializableFires() {
		// API 33+ added the type-token overload getSerializable(String, Class<T>).
		assertTrue(fires("MyType t = intent.getSerializable(\"key\", MyType.class);"),
				"the API 33+ two-arg getSerializable(name, Class) overload is still a forged-object entry");
	}

	@Test
	void unrelatedBundleGetterDoesNotFire() {
		assertFalse(fires("String s = intent.getStringExtra(\"key\");"),
				"getStringExtra returns a primitive String, not a forgeable object — must not fire");
		assertFalse(fires("int i = intent.getIntExtra(\"key\", 0);"),
				"getIntExtra returns a primitive — must not fire");
	}

	@Test
	void getParcelableNotConfusedWithArrayVariants() {
		// The array variants must not be swallowed by the bare getParcelableExtra branch ordering:
		// every variant maps to the same kind, so order does not matter, but the regex must match
		// the longest/most-specific variant too.
		assertTrue(fires("getParcelableArrayExtra(\"x\");"));
		assertTrue(fires("getParcelableArrayListExtra(\"x\");"));
	}
}
