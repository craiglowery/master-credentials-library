package com.craiglowery.java.master_credentials_library;

public class BackingStoreException extends RuntimeException {

    public BackingStoreException(String message) {
        super(message);
    }

    public BackingStoreException(String message, Throwable cause) {
        super(message, cause);
    }
}
