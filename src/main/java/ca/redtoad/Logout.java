package ca.redtoad;

import java.util.Optional;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.pac4j.core.context.J2EContext;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.profile.ProfileManager;
import org.pac4j.core.redirect.RedirectAction;
import org.pac4j.saml.client.SAML2Client;
import org.pac4j.saml.profile.SAML2Profile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Logout
    extends HttpServlet
{
  private static Logger log = LoggerFactory.getLogger(Logout.class);

  private final SAML2ClientBuilder saml2ClientBuilder = new SAML2ClientBuilder();

  protected void doGet(HttpServletRequest request, HttpServletResponse response) {
    try {
      WebContext context = new J2EContext(request, response);
      SAML2Client client = saml2ClientBuilder.build();
      ProfileManager<SAML2Profile> profileManager = new ProfileManager<>(context);
      Optional<SAML2Profile> profile = profileManager.get(true);
      if (profile.isPresent()) {
        log.info("Logout IdP");
        log.info("profile = " + profile.get());
        // Logout at IdP
        RedirectAction action = client.getLogoutAction(context, profile.get(), null);
        // If you only want to logout here (at the SP) and not also at the IdP
        // then you need to call /callback with logoutendpoint=true directly instead
        // otherwise this will logout at the IdP, which will call /callback with logoutendpoint=true
        action.perform(context);
      }
    }
    catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
