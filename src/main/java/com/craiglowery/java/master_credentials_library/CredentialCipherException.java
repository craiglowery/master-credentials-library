package com.craiglowery.java.master_credentials_library;

/**
 * Thrown when encryption or decryption of a credential value fails, e.g. due to
 * a wrong master key, tampered or corrupted ciphertext, or an unsupported or
 * malformed payload.
 */
public class CredentialCipherException extends RuntimeException {

    public CredentialCipherException(String message) {
        super(message);
    }

    public CredentialCipherException(String message, Throwable cause) {
        super(message, cause);
    }
}
