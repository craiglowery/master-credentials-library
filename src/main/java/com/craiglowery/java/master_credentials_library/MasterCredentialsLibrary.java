package com.craiglowery.java.master_credentials_library;


import org.jetbrains.annotations.NotNull;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * A key/value store for keeping any text, such as a JSON object, encrypted.
 *
 * <p>A master key is used to derive an AES encryption key via PBKDF2 and is required
 * at construction time. The key can be provided via an environment variable or as a
 * parameter to the constructor. The derived key is computed once at construction time
 * and cached; the master key itself is not retained afterward.</p>
 *
 * <p>Encrypted values are stored as Base64 text of the form
 * {@code version(1 byte) || iv(12 bytes) || AES/GCM ciphertext+tag}, so the payload
 * format can evolve in the future without breaking previously stored values.</p>
 *
 * <p>This is an abstract class. Implementations must be provided to store and retrieve
 * encrypted text given a key.</p>
 */
public abstract class MasterCredentialsLibrary {

    private static final String MCL_MASTER_KEY = "MCL_KEY";

    /** Minimum number of characters required in a master key. */
    private static final int MIN_KEY_LENGTH = 64;

    /** Minimum number of distinct characters required, as a coarse entropy sanity check. */
    private static final int MIN_DISTINCT_CHARACTERS = 24;

    /**
     * Fixed domain-separation salt for PBKDF2 key derivation. This is not a substitute
     * for master key entropy (enforced separately) - it exists so this library's key
     * derivation does not collide with other uses of the same master key material.
     */
    private static final byte[] KDF_SALT =
            "MasterCredentialLibrary-v1".getBytes(StandardCharsets.UTF_8);

    private static final int KDF_ITERATIONS = 210_000;
    private static final int KEY_LENGTH_BITS = 256;

    private static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int IV_LENGTH_BYTES = 12;
    private static final int GCM_TAG_LENGTH_BITS = 128;

    /** Version tag prefixed to every encrypted payload, to allow the format to evolve. */
    private static final byte FORMAT_VERSION = 1;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final SecretKeySpec secretKey;

    /**
     * Constructs a new instance, reading the master key from the {@code MCL_KEY}
     * environment variable.
     *
     * @throws InvalidMasterKeyException if the {@code MCL_KEY} environment variable is
     *                                    not set, or the key does not meet the minimum
     *                                    strength requirements
     */
    public MasterCredentialsLibrary() {
        this(readMasterKeyFromEnvironment());
    }

    /**
     * Constructs a new instance using the given master key.
     *
     * <p>The key is used only to derive the AES encryption key during construction;
     * it is not retained by this instance afterward.</p>
     *
     * @param masterKey the master key used to derive the encryption key; must not be null
     * @throws NullPointerException      if {@code masterKey} is null
     * @throws InvalidMasterKeyException if the key does not meet the minimum strength
     *                                    requirements
     */
    public MasterCredentialsLibrary(@NotNull String masterKey) {
        Objects.requireNonNull(masterKey, "masterKey must not be null");
        this.secretKey = deriveKey(masterKey);
    }

    /**
     * Retrieves the raw (encrypted) value stored for the given key from the backing store.
     *
     * <p>Implementations must return {@code null} if no value is stored for the key.</p>
     *
     * @param key the key to look up; must not be null
     * @return the stored ciphertext, or {@code null} if no value exists for the key
     */
    protected abstract String getFromBackingStore(@NotNull String key) throws BackingStoreException;

    /**
     * Persists the given encrypted value for the given key to the backing store.  If a value already
     * exists for the key, it is overwritten.
     *
     * @param key   the key under which to store the value; must not be null
     * @param value the ciphertext to store; must not be null
     */
    protected abstract void setToBackingStore(@NotNull String key, @NotNull String value) throws BackingStoreException;

    /**
     * Retrieves and decrypts the value stored for the given key.
     *
     * @param key the key to look up; must not be null
     * @return the decrypted value, or {@link Optional#empty()} if no value exists for the key
     * @throws CredentialCipherException if decryption fails
     */
    public Optional<String> get(@NotNull String key) {
        Objects.requireNonNull(key);
        String cipherText = getFromBackingStore(key);
        if (cipherText == null) {
            return Optional.empty();
        }
        return Optional.of(decrypt(cipherText));
    }

    /**
     * Encrypts the given value and stores it under the given key.
     *
     * @param key   the key under which to store the value; must not be null
     * @param value the plaintext value to encrypt and store; must not be null
     * @throws CredentialCipherException if encryption fails
     */
    public void set(@NotNull String key, @NotNull String value) {
        Objects.requireNonNull(key);
        Objects.requireNonNull(value);
        setToBackingStore(key, encrypt(value));
    }


    private static String readMasterKeyFromEnvironment() {
        String key = System.getenv(MCL_MASTER_KEY);
        if (key == null) {
            throw new InvalidMasterKeyException(
                    "Master key environment variable (" + MCL_MASTER_KEY + ") is not set");
        }
        return key;
    }

    /**
     * Validates the given master key and derives an AES key from it via PBKDF2.
     *
     * <p>The master key is copied into a {@code char[]} so it can be explicitly cleared
     * from memory as soon as derivation completes, rather than lingering as an immutable
     * {@code String} for the lifetime of the JVM.</p>
     *
     * @throws InvalidMasterKeyException if the key is too short, too low in character
     *                                    diversity, or key derivation otherwise fails
     */
    private static SecretKeySpec deriveKey(String masterKey) {
        char[] keyChars = masterKey.toCharArray();
        try {
            validateKeyStrength(keyChars);

            PBEKeySpec spec = new PBEKeySpec(keyChars, KDF_SALT, KDF_ITERATIONS, KEY_LENGTH_BITS);
            try {
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                byte[] keyBytes = factory.generateSecret(spec).getEncoded();
                try {
                    return new SecretKeySpec(keyBytes, "AES");
                } finally {
                    Arrays.fill(keyBytes, (byte) 0);
                }
            } finally {
                spec.clearPassword();
            }
        } catch (GeneralSecurityException e) {
            throw new InvalidMasterKeyException("Unable to derive encryption key from master key", e);
        } finally {
            Arrays.fill(keyChars, '\0');
        }
    }

    /**
     * Performs minimum-length and coarse character-diversity checks on the master key.
     * This is not a rigorous entropy measurement, but it rejects obviously weak keys
     * (e.g. a long run of the same repeated character) that a pure length check would miss.
     *
     * @throws InvalidMasterKeyException if the key is too short or too low in diversity
     */
    private static void validateKeyStrength(char[] key) {
        if (key.length < MIN_KEY_LENGTH) {
            throw new InvalidMasterKeyException(
                    "Master key must be at least " + MIN_KEY_LENGTH + " characters long");
        }
        Set<Character> distinctCharacters = new HashSet<>();
        for (char c : key) {
            distinctCharacters.add(c);
        }
        if (distinctCharacters.size() < MIN_DISTINCT_CHARACTERS) {
            throw new InvalidMasterKeyException(
                    "Master key has too little character diversity to provide adequate entropy "
                            + "(found " + distinctCharacters.size() + " distinct characters, need at least "
                            + MIN_DISTINCT_CHARACTERS + ")");
        }
    }

    /**
     * Encrypts the given plaintext using AES/GCM with the key derived at construction time.
     *
     * <p>A random 12-byte initialization vector (IV) is generated for each call. The
     * stored payload is {@code version || iv || ciphertext+tag}, Base64-encoded.</p>
     *
     * @param text the plaintext to encrypt; must not be null
     * @return the Base64-encoded versioned payload
     * @throws CredentialCipherException if encryption fails
     */
    private String encrypt(@NotNull String text) {
        Objects.requireNonNull(text);

        try {
            byte[] iv = new byte[IV_LENGTH_BYTES];
            SECURE_RANDOM.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));

            byte[] encryptedBytes = cipher.doFinal(text.getBytes(StandardCharsets.UTF_8));

            ByteBuffer byteBuffer = ByteBuffer.allocate(1 + iv.length + encryptedBytes.length);
            byteBuffer.put(FORMAT_VERSION);
            byteBuffer.put(iv);
            byteBuffer.put(encryptedBytes);

            return Base64.getEncoder().encodeToString(byteBuffer.array());
        } catch (GeneralSecurityException e) {
            throw new CredentialCipherException("Unable to encrypt text", e);
        }
    }

    /**
     * Decrypts a value previously produced by {@link #encrypt(String)}.
     *
     * @param text the Base64-encoded versioned payload to decrypt; must not be null
     * @return the decrypted plaintext
     * @throws CredentialCipherException if the payload is malformed, uses an unsupported
     *                                    format version, or decryption fails, e.g. due to
     *                                    a wrong master key or tampered/corrupted data
     */
    private String decrypt(@NotNull String text) {
        Objects.requireNonNull(text);

        byte[] payload;
        try {
            payload = Base64.getDecoder().decode(text);
        } catch (IllegalArgumentException e) {
            throw new CredentialCipherException("Encrypted payload is not valid Base64", e);
        }

        if (payload.length < 1 + IV_LENGTH_BYTES) {
            throw new CredentialCipherException("Encrypted payload is too short to be valid");
        }

        ByteBuffer byteBuffer = ByteBuffer.wrap(payload);

        byte version = byteBuffer.get();
        if (version != FORMAT_VERSION) {
            throw new CredentialCipherException("Unsupported encrypted payload version: " + version);
        }

        byte[] iv = new byte[IV_LENGTH_BYTES];
        byteBuffer.get(iv);

        byte[] encryptedBytes = new byte[byteBuffer.remaining()];
        byteBuffer.get(encryptedBytes);

        try {
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));

            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            try {
                return new String(decryptedBytes, StandardCharsets.UTF_8);
            } finally {
                Arrays.fill(decryptedBytes, (byte) 0);
            }
        } catch (GeneralSecurityException e) {
            throw new CredentialCipherException(
                    "Unable to decrypt text (wrong master key or corrupted/tampered data)", e);
        }
    }

}
