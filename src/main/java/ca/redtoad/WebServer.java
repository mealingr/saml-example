package ca.redtoad;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletContextHandler;

public class WebServer
{
  private Server server;

  public void start() throws Exception {
    ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
    context.setContextPath("/");
    server = new Server(8081);
    server.setHandler(context);
    context.addServlet(Secure.class, "/secure/*");
    context.addServlet(Login.class, "/login/*");
    context.addServlet(Logout.class, "/logout/*");
    context.addServlet(Callback.class, "/callback/*");
    context.addServlet(Metadata.class, "/metadata/*");
    context.addServlet(Home.class, "/");
    server.start();
  }
}
