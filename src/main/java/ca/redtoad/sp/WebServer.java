package ca.redtoad.sp;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletContextHandler;

public class WebServer
{
  public void start() throws Exception {
    ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
    context.setContextPath("/");
    Server server = new Server(8081);
    server.setHandler(context);
    context.addServlet(Secure.class, "/secure/*");
    context.addServlet(Login.class, "/login/*");
    context.addServlet(Logout.class, "/logout/*");
    context.addServlet(CallbackLogin.class, "/callback/login/*");
    context.addServlet(CallbackLogout.class, "/callback/logout/*");
    context.addServlet(CallbackECP.class, "/callback/ecp/*");
    context.addServlet(Metadata.class, "/metadata/*");
    context.addServlet(Home.class, "/");
    server.start();
  }
}
