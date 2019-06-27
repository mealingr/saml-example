package ca.redtoad;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.pac4j.core.context.J2EContext;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.profile.ProfileManager;
import org.pac4j.saml.client.SAML2Client;
import org.pac4j.saml.credentials.SAML2Credentials;
import org.pac4j.saml.profile.SAML2Profile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Callback
    extends HttpServlet
{
  private static final Logger log = LoggerFactory.getLogger(Callback.class);

  private final SAML2ClientBuilder saml2ClientBuilder = new SAML2ClientBuilder();

  protected void doGet(HttpServletRequest request, HttpServletResponse response) {
    try {
      String logoutendpoint = request.getParameter("logoutendpoint");
      if ("true".equalsIgnoreCase(logoutendpoint)) {
        log.info("Logout SP");
        WebContext context = new J2EContext(request, response);
        ProfileManager<SAML2Profile> profileManager = new ProfileManager<>(context);
        // Logout from SP
        profileManager.logout();
        response.sendRedirect("/");
      }
    }
    catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  protected void doPost(HttpServletRequest request, HttpServletResponse response) {
    try {
      WebContext context = new J2EContext(request, response);
      SAML2Client client = saml2ClientBuilder.build();
      SAML2Credentials credentials = client.getCredentials(context);
      SAML2Profile profile = client.getUserProfile(credentials, context);

      log.info("received done message");
      log.info("credentials = " + credentials);
      log.info("profile = " + profile);

      // Normally once we have the credentials and the profile we would do further checks 
      // to see how the logged in IdP user maps to our SP user e.g. in this example we might look them up internally 
      // using their e-mail credentials.getUserProfile().getEmail()
      // using their groups credentials.getUserProfile().getAttribute("eduPersonAffiliation")
      // etc

      ProfileManager<SAML2Profile> profileManager = new ProfileManager<>(context);
      profileManager.save(true, profile, false);

      HttpSession session = request.getSession();
      response.sendRedirect((String) session.getAttribute("redirecturl"));
    }
    catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
