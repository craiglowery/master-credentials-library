module com.craiglowery.java.master_credentials_library {
    requires com.craiglowery.java.postgrespool;
    requires java.sql;
    requires org.jetbrains.annotations;
    requires com.craiglowery.java.commandinterpreter;
    requires com.craiglowery.java.ini_loader;
    exports com.craiglowery.java.master_credentials_library;
}