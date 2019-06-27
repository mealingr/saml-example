package ca.redtoad;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.pac4j.core.context.J2EContext;
import org.pac4j.core.context.WebContext;
import org.pac4j.saml.client.SAML2Client;

public class Login
    extends HttpServlet
{
  private final SAML2ClientBuilder saml2ClientBuilder = new SAML2ClientBuilder();

  protected void doGet(HttpServletRequest request, HttpServletResponse response) {
    try {
      WebContext context = new J2EContext(request, response);
      SAML2Client client = saml2ClientBuilder.build();
      client.redirect(context);
    }
    catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
