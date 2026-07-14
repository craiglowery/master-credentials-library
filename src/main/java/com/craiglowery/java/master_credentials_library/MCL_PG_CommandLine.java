package com.craiglowery.java.master_credentials_library;


import com.craiglowery.java.commandinterpreter.CommandInterpreter;
import com.craiglowery.java.postgrespool.ConnectionPool;
import com.craiglowery.java.postgrespool.ParameterizedStatement;
import com.craiglowery.java.postgrespool.PooledConnection;
import com.craiglowery.java.ini_loader.IniLoader;

import java.net.URI;
import java.sql.ResultSet;
import java.util.Optional;

/**
 * Implements a command line interface for the Master Credential Library on a PostgreSQL database.
 *
 * <p>Requires that the following environment variables are set:</p>
 * <ul>
 *     <li>MCL_PG_URL - the JDBC URL of the PostgreSQL database</li>
 *     <li>MCL_MASTER_KEY - the master key used to encrypt credential values</li>
 * </ul>
 */
public class MCL_PG_CommandLine {

    public static void usage() {
        System.out.println(
                """
                        Usage:
                        
                           mclpg add <key> "<value>"
                           mclpg list
                           mclpg get <key>
                           exit
                        
                        NOTES: Environment variables MCL_PG_URL and MCL_MASTER_KEY must be set.
                        """
        );
    }

    public void process(MasterCredentialsLibraryPostgres mcl, PooledConnection conn, String[] args) {
        try {
            switch (args[0]) {
                case "add" -> {
                    if (args.length != 3)
                        throw new Exception();
                    String key = args[1];
                    String value = args[2];
                    assert key != null;
                    assert value != null;
                    mcl.set(key, value);
                    System.out.println("Added " + key);
                }
                case "list" -> {
                    System.out.println("Listing all keys:");
                    try (ParameterizedStatement statement = conn.parameterizedStatement("SELECT key FROM mcl_keys")) {
                        ResultSet resultSet = statement.executeQuery();
                        while (resultSet.next()) {
                            System.out.println("  " + resultSet.getString(1));
                        }
                    }
                }
                case "get" -> {
                    if (args.length != 2) usage();
                    String key = args[1];
                    assert key != null;
                    System.out.println("Value for " + key + ": " + mcl.get(key).orElse("not found"));
                }
                case "delete" -> {
                    if (args.length != 2) usage();
                    String key = args[1];
                    assert key != null;
                    try (ParameterizedStatement statement = conn.parameterizedStatement("DELETE FROM mcl_keys WHERE key = ?", key)) {
                        if (statement.executeUpdate() != 1) {
                            System.out.println("Failed to delete " + key + " - it may not exist");
                        } else {
                            System.out.println("Deleted " + key);
                        }
                    }
                }
            }
        } catch (Exception e) {
                usage();
        }

    }

    public MCL_PG_CommandLine() throws Exception{

        IniLoader ini = new IniLoader("D:\\UserData\\CraigLowery\\Libraries\\Other\\.secrets\\secrets.ini");

        Optional<String> url = ini.getValue("Secrets","MCL_PG_URL");
        Optional<String> masterKey = ini.getValue("Secrets","MCL_MASTER_KEY");
        if (url.isEmpty())
            throw new RuntimeException("MCL_PG_URL environment variable must be set");
        if (masterKey.isEmpty())
            throw new RuntimeException("MCL_MASTER_KEY environment variable must be set");
        URI uri = URI.create(url.get());
        try (final ConnectionPool pool = new ConnectionPool(uri);
             final PooledConnection conn = pool.getPooledConnection()) {
            MasterCredentialsLibraryPostgres mcl = new MasterCredentialsLibraryPostgres(masterKey.get(), conn);
            CommandInterpreter ci = new CommandInterpreter();
            ci.addCommand("^add\\s+(\\w+)\\s+\\\"(.*)\\\"$","add <key> \"<value>\"",
                    """
                    Add a key value pair.
                    """,
                    (matcher ->  {
                        mcl.set(matcher.group(1), matcher.group(2));
                        if (mcl.get(matcher.group(1)).isEmpty()) {
                            System.out.println("New value was not added - unknown reason why");
                        } else if (!mcl.get(matcher.group(1)).get().equals(matcher.group(2))) {
                            System.out.println("Value added apparently got mangled - retrieved value does not match original");
                        } else {
                            System.out.println("Added " + matcher.group(1));
                        }
                    })
                    );
            ci.addCommand("^delete\\s+(\\w+)$","delete <key>","Delete a key value pair",
                    (matcher ->  {
                        String key = matcher.group(1);
                        try (ParameterizedStatement statement = conn.parameterizedStatement("DELETE FROM "+mcl.getTableName()+" WHERE key = ?", key)) {
                            if (statement.executeUpdate() != 1) {
                                System.out.println("Failed to delete " + key + " - it may not exist");
                            } else {
                                System.out.println("Deleted " + key);
                            }
                        } catch (Exception e) {
                            System.err.println("Database error: " + e.getMessage());
                        }
                    })
                    );
            ci.addCommand("list","list","List all keys", (matcher) -> {
                System.out.println("Listing all keys:");
                try (ParameterizedStatement statement = conn.parameterizedStatement("SELECT key FROM "+mcl.getTableName())) {
                    ResultSet resultSet = statement.executeQuery();
                    while (resultSet.next()) {
                        System.out.println("  " + resultSet.getString(1));
                    }
                } catch (Exception e) {
                    System.err.println("Database error: " + e.getMessage());
                }
            });
            ci.addCommand("^get\\s+(\\w+)$","get <key>","Get the value of a key", (matcher -> {
                String key = matcher.group(1);
                System.out.println("Value for " + key + ": " + mcl.get(key).orElse("not found"));
            }));

            ci.interpreter();

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }


    }
        public static void main(String[] args) {
                try {
                    new MCL_PG_CommandLine();
                }
                catch (Exception e) {
                    e.printStackTrace();
                }
            }

}
