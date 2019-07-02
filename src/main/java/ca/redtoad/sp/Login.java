package ca.redtoad.sp;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Login
    extends HttpServlet
{
  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response) {
    String destination = SAMLUtil.getIdentityProviderSingleSignOnServiceRedirectDestination();
    SAMLUtil.sendAuthnRequestViaPost(response, SAMLUtil.buildAuthnRequest(destination));
    // SAMLUtil.sendAuthnRequestViaRedirect(response, SAMLUtil.buildAuthnRequest(destination));
  }
}
