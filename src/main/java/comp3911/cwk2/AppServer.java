package comp3911.cwk2;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletHandler;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.eclipse.jetty.util.log.Log;
import org.eclipse.jetty.util.log.StdErrLog;

public class AppServer {
  public static void main(String[] args) throws Exception {
    Log.setLog(new StdErrLog());

    ServletHandler handler = new ServletHandler();
    handler.addServletWithMapping(AppServlet.class, "/*");

    Server server = new Server();
    server.setHandler(handler);

    // Fixes for 1.2 (use ServerConnector and sslContextFactory for HTTPS connection)
    SslContextFactory.Server sslContextFactory = new SslContextFactory.Server();
    sslContextFactory.setKeyStorePath("keystore.jks");
    sslContextFactory.setKeyStorePassword("password");

    ServerConnector httpsServer = new ServerConnector(server, sslContextFactory);
    httpsServer.setPort(8080);

    server.addConnector(httpsServer);

    server.start();
    server.join();
  }
}
