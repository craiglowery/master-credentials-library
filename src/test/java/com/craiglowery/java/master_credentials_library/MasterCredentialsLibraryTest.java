package com.craiglowery.java.master_credentials_library;

import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MasterCredentialsLibraryTest {

    // 80 characters, high diversity - satisfies both length and distinct-character checks.
    private static final String VALID_KEY =
            "aB3$fG7!kL9@qR2#tY5^wZ8&cD1*eH4(jN6)mP0-uS_vX+oQ=iW.hK,gT/bF;nJ:zC";

    private static final String OTHER_VALID_KEY =
            "1qA!2wS@3eD#4rF$5tG%6yH^7uJ&8iK*9oL(0pZ)aQ_bW-cE+dR=fT.gY,hU/jI;kO";

    private static class InMemoryLibrary extends MasterCredentialsLibrary {
        private final Map<String, String> store = new HashMap<>();

        InMemoryLibrary(String masterKey) {
            super(masterKey);
        }

        @Override
        protected String getFromBackingStore(@NotNull String key) {
            return store.get(key);
        }

        @Override
        protected void setToBackingStore(@NotNull String key, @NotNull String value) {
            store.put(key, value);
        }
    }

    @Test
    void roundTripEncryptsAndDecryptsValue() {
        InMemoryLibrary lib = new InMemoryLibrary(VALID_KEY);

        lib.set("username", "craig");

        assertEquals(Optional.of("craig"), lib.get("username"));
    }

    @Test
    void storedValueIsNotPlaintext() {
        InMemoryLibrary lib = new InMemoryLibrary(VALID_KEY);

        lib.set("secret", "super-secret-value");

        assertTrue(lib.store.containsKey("secret"));
        assertTrue(!lib.store.get("secret").contains("super-secret-value"));
    }

    @Test
    void missingKeyReturnsEmptyOptional() {
        InMemoryLibrary lib = new InMemoryLibrary(VALID_KEY);

        assertEquals(Optional.empty(), lib.get("does-not-exist"));
    }

    @Test
    void decryptingWithWrongMasterKeyFails() {
        InMemoryLibrary writer = new InMemoryLibrary(VALID_KEY);
        writer.set("password", "hunter2");
        String stored = writer.store.get("password");

        InMemoryLibrary reader = new InMemoryLibrary(OTHER_VALID_KEY);
        reader.store.put("password", stored);

        assertThrows(CredentialCipherException.class, () -> reader.get("password"));
    }

    @Test
    void tamperedCiphertextFailsAuthentication() {
        InMemoryLibrary lib = new InMemoryLibrary(VALID_KEY);
        lib.set("token", "abc123");
        String stored = lib.store.get("token");

        // Flip a character in the middle of the Base64 payload to simulate tampering.
        int mid = stored.length() / 2;
        char flipped = stored.charAt(mid) == 'A' ? 'B' : 'A';
        String tampered = stored.substring(0, mid) + flipped + stored.substring(mid + 1);
        lib.store.put("token", tampered);

        assertThrows(CredentialCipherException.class, () -> lib.get("token"));
    }

    @Test
    void malformedPayloadFailsCleanly() {
        InMemoryLibrary lib = new InMemoryLibrary(VALID_KEY);
        lib.store.put("bad", "not-valid-base64!!");

        assertThrows(CredentialCipherException.class, () -> lib.get("bad"));
    }

    @Test
    void tooShortMasterKeyIsRejected() {
        assertThrows(InvalidMasterKeyException.class, () -> new InMemoryLibrary("short-key"));
    }

    @Test
    void lowDiversityMasterKeyIsRejected() {
        String repeated = "a".repeat(80);

        assertThrows(InvalidMasterKeyException.class, () -> new InMemoryLibrary(repeated));
    }

    @Test
    void nullMasterKeyIsRejected() {
        assertThrows(NullPointerException.class, () -> new InMemoryLibrary(null));
    }
}
