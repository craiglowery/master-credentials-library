package com.craiglowery.java.master_credentials_library;

/**
 * An interface for factory classes that create a {@link MasterCredentialsLibrary} instance
 * with a default configuration.
 */
public interface AutoProvider {
    public MasterCredentialsLibrary create() throws BackingStoreException;
}
