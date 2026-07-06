package jadx.ai.cli.commands;

import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the {@code gson_runtime_type_adapter} rule in {@link SerializationScanCommand}.
 *
 * <p>Gson's {@code RuntimeTypeAdapterFactory} (and the {@code @JsonSubTypes}/
 * {@code registerSubtype} annotations it mirrors) is the Gson equivalent of Jackson default
 * typing: the JSON carries a type discriminator field, and the factory picks a concrete class to
 * deserialize into from it. When the discriminator is attacker-controlled this is a
 * deserialization gadget surface every bit as real as {@code enableDefaultTyping} — yet the old
 * rule set only flagged Jackson's API, silently missing the Gson form that is common in
 * Android networking layers.
 */
class SerializationGsonRuntimeTypeTest {

	private static final Pattern RULE = Pattern.compile(SerializationScanCommand.GSON_RUNTIME_TYPE.pattern());

	private static boolean fires(String line) {
		return RULE.matcher(line).find();
	}

	@Test
	void runtimeTypeAdapterFactoryFires() {
		assertTrue(fires("RuntimeTypeAdapterFactory.of(Foo.class, \"type\")"),
				"RuntimeTypeAdapterFactory is the canonical Gson polymorphic-deserialization gadget");
		assertTrue(fires("RuntimeTypeAdapterFactory<Bar> f = RuntimeTypeAdapterFactory.of(Bar.class);"),
				"a stored RuntimeTypeAdapterFactory field must fire");
	}

	@Test
	void jsonSubTypesAnnotationFires() {
		assertTrue(fires("@JsonSubTypes({ @JsonSubTypes.Type(ImplA.class) })"),
				"@JsonSubTypes pins the polymorphic subtype set — must fire");
	}

	@Test
	void registerSubtypeFires() {
		assertTrue(fires("runtimeTypeAdapterFactory.registerSubtype(ImplB.class, \"b\");"),
				"registerSubtype adds a runtime-resolvable subtype — must fire");
	}

	@Test
	void plainGsonWithoutPolymorphismDoesNotFire() {
		assertFalse(fires("Gson gson = new GsonBuilder().create();"),
				"a plain GsonBuilder with no type-polymorphic factory is not a gadget surface");
		assertFalse(fires("Foo f = gson.fromJson(json, Foo.class);"),
				"fromJson into a fixed concrete type is not polymorphic deserialization");
	}

	@Test
	void jacksonDefaultTypingNotConfusedWithGson() {
		// Jackson's API stays on its own rule; the Gson rule must not double-fire on Jackson code,
		// and vice-versa. (This is a same-line uniqueness guard via the first-match-wins RULES order,
		// not the regex — the regexes are disjoint by design.)
		assertFalse(fires("objectMapper.enableDefaultTyping();"),
				"Jackson's enableDefaultTyping is not a Gson RuntimeTypeAdapterFactory");
	}
}
