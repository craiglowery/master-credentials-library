package com.craiglowery.java.master_credentials_library;

import com.craiglowery.java.postgrespool.PooledConnection;
import com.craiglowery.java.postgrespool.ParameterizedStatement;
import org.jetbrains.annotations.NotNull;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Objects;


/**
 * PostgreSQL-backed implementation of {@link MasterCredentialsLibrary} that stores
 * encrypted credential values as rows of {@code (key, value)} text in a single table,
 * created automatically if it does not already exist.
 *
 * <h2>Construction and lifecycle</h2>
 * <p>Constructing an instance issues a {@code CREATE TABLE IF NOT EXISTS} statement
 * against the given connection. Because of this, instances are meant to be created
 * infrequently - typically once, and held for reuse - rather than constructed per
 * operation or per request.</p>
 *
 * <h2>Connection ownership</h2>
 * <p>The {@link PooledConnection} passed to the constructor is used for every
 * backing-store operation performed by this instance, but its lifecycle is not managed
 * by this class. This class never closes the connection or returns it to the pool. The
 * caller is responsible for checking the connection out of the pool before construction
 * and returning it (e.g. via {@code connection.close()}) once this instance is no longer
 * needed.</p>
 *
 * <h2>Thread safety</h2>
 * <p>This class is <b>not</b> thread-safe. It holds a single {@link PooledConnection} for
 * its entire lifetime, and JDBC connections are not safe for concurrent use by multiple
 * threads. Instances must be confined to a single thread, or all access to a shared
 * instance must be externally synchronized.</p>
 */
public class MasterCredentialsLibraryPostgres extends MasterCredentialsLibrary {

    /** Name of the table used to store encrypted key/value pairs. */
    private final String tableName="mcl_backing_store";

    public String getTableName() {return tableName;}

    /**
     * The connection used for all backing-store operations. Ownership is retained by the
     * caller; this class never closes it or returns it to the pool. See the class
     * documentation for details.
     */
    private final PooledConnection connection;

    /**
     * Constructs a new instance using the given master key, and ensures the backing table
     * exists on the given connection.
     *
     * <p>See the class documentation for important caveats about construction frequency,
     * connection ownership, and thread safety.</p>
     *
     * @param masterKey  the master key used to derive the encryption key; must not be null
     * @param connection the connection to use for all backing-store operations; must not
     *                    be null. Ownership is not transferred - the caller remains
     *                    responsible for returning it to the pool
     * @throws NullPointerException      if {@code masterKey} or {@code connection} is null
     * @throws InvalidMasterKeyException if the master key does not meet the minimum
     *                                    strength requirements enforced by
     *                                    {@link MasterCredentialsLibrary}
     * @throws BackingStoreException     if the backing table cannot be created
     */
    public MasterCredentialsLibraryPostgres(@NotNull String masterKey, @NotNull PooledConnection connection) {
        Objects.requireNonNull(connection);
        super(masterKey);
        this.connection=connection;
        createTables();
    }

    /**
     * Constructs a new instance, reading the master key from the {@code MCL_KEY}
     * environment variable (see {@link MasterCredentialsLibrary#MasterCredentialsLibrary()}),
     * and ensures the backing table exists on the given connection.
     *
     * <p>See the class documentation for important caveats about construction frequency,
     * connection ownership, and thread safety.</p>
     *
     * @param connection the connection to use for all backing-store operations; must not
     *                    be null. Ownership is not transferred - the caller remains
     *                    responsible for returning it to the pool
     * @throws NullPointerException      if {@code connection} is null
     * @throws InvalidMasterKeyException if the {@code MCL_KEY} environment variable is not
     *                                    set, or the key does not meet the minimum strength
     *                                    requirements
     * @throws BackingStoreException     if the backing table cannot be created
     */
    public MasterCredentialsLibraryPostgres(@NotNull PooledConnection connection) {
        Objects.requireNonNull(connection);
        super();
        this.connection=connection;
        createTables();
    }

    /**
     * Creates the backing table if it does not already exist.
     *
     * @throws BackingStoreException if table creation fails
     */
    private void createTables()  {
        try {
            connection.execute("CREATE TABLE IF NOT EXISTS " + tableName + " (key TEXT PRIMARY KEY, value TEXT)");
        } catch (Exception e) {
            throw new BackingStoreException("Unable to create backing store table: " + e.getMessage(),e);
        }
    }

    /**
     * {@inheritDoc}
     *
     * @throws BackingStoreException if the query fails
     */
    @Override
    protected String getFromBackingStore(@NotNull String key) throws BackingStoreException {
        Objects.requireNonNull(key);
        try (ParameterizedStatement parameterizedStatement = connection.parameterizedStatement("SELECT value FROM "+tableName+" WHERE key=?",key)) {
            ResultSet resultSet = parameterizedStatement.executeQuery();
            if (resultSet.next()) {
                return resultSet.getString(1);
            }
            return null;
        } catch (SQLException e) {
            throw new BackingStoreException("Unable to retrieve value from backing store: " + e.getMessage(),e);
        }
    }

    /**
     * {@inheritDoc}
     *
     * <p>Implemented as an upsert ({@code INSERT ... ON CONFLICT (key) DO UPDATE}), so a
     * value already stored under {@code key} is overwritten.</p>
     *
     * @throws BackingStoreException if the insert/update fails, or unexpectedly affects a
     *                                row count other than 1
     */
    @Override
    protected void setToBackingStore(@NotNull String key, @NotNull String value) throws BackingStoreException{
        Objects.requireNonNull(key);
        Objects.requireNonNull(value);
        try (ParameterizedStatement parameterizedStatement = connection.parameterizedStatement("INSERT INTO "+tableName+" (key,value) VALUES (?,?) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value",key, value)) {
            if (parameterizedStatement.executeUpdate() != 1) {
                throw new BackingStoreException("Unable to set value in backing store: no rows affected");
            }
        } catch (SQLException e) {
            throw new BackingStoreException("Unable to set value in backing store: " + e.getMessage(),e);
        }
    }
}
