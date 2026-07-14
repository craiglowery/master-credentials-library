package com.craiglowery.java.master_credentials_library;

/**
 * Thrown when a master key is missing, malformed, or does not meet the minimum
 * strength requirements enforced by {@link MasterCredentialsLibrary}.
 */
public class InvalidMasterKeyException extends RuntimeException {

    public InvalidMasterKeyException(String message) {
        super(message);
    }

    public InvalidMasterKeyException(String message, Throwable cause) {
        super(message, cause);
    }
}
