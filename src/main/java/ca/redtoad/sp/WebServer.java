package ca.redtoad.sp;

import java.util.EnumSet;

import javax.servlet.DispatcherType;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.FilterHolder;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;
import org.springframework.web.context.ContextLoaderListener;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.filter.DelegatingFilterProxy;

public class WebServer
{
  public void start() throws Exception {
    ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
    context.setContextPath("/");
    context.addServlet(Home.class, "/");
    context.addServlet(Secure.class, "/secure/*");

    AnnotationConfigWebApplicationContext annotationConfigWebApplicationContext =
        new AnnotationConfigWebApplicationContext();
    annotationConfigWebApplicationContext.setConfigLocation("ca.redtoad.sp");
    context.addEventListener(new ContextLoaderListener(annotationConfigWebApplicationContext));
    context.addFilter(
        new FilterHolder(new DelegatingFilterProxy(AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME)),
        "/*", EnumSet.allOf(DispatcherType.class));

    Server server = new Server(8081);
    server.setHandler(context);
    server.start();
  }
}
