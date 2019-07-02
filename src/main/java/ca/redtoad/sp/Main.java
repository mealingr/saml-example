package ca.redtoad.sp;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import org.slf4j.LoggerFactory;

public class Main
{
  public static void main(String[] args) throws Exception {
    Logger root = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
    root.setLevel(Level.INFO);
    SAMLUtil.initSAML();
    WebServer webServer = new WebServer();
    webServer.start();
  }
}
