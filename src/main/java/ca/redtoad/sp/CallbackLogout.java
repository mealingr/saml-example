package ca.redtoad.sp;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.util.encoders.Base64;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.LogoutResponse;

public class CallbackLogout
    extends HttpServlet
{
  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
    String samlRequest = request.getParameter("SAMLRequest");
    if (samlRequest != null) {
      samlRequest = new String(Base64.decode(samlRequest), StandardCharsets.UTF_8);
      LogoutRequest logoutRequest = (LogoutRequest) SAMLUtil.unmarshall(samlRequest);
      SAMLUtil.verifySignature(logoutRequest, Credential.getIdentityProviderCredential());
      request.getSession().invalidate();
      String destination = SAMLUtil.getIdentityProviderSingleLogoutServiceRedirectDestination();
      SAMLUtil.sendLogoutResponseViaPost(response, SAMLUtil.buildLogoutResponse(logoutRequest, destination));
      // SAMLUtil.sendLogoutResponseViaRedirect(response, SAMLUtil.buildLogoutResponse(logoutRequest, destination));
    }
    String samlResponse = request.getParameter("SAMLResponse");
    if (samlResponse != null) {
      samlResponse = new String(Base64.decode(samlResponse), StandardCharsets.UTF_8);
      LogoutResponse logoutResponse = (LogoutResponse) SAMLUtil.unmarshall(samlResponse);
      SAMLUtil.verifySignature(logoutResponse, Credential.getIdentityProviderCredential());
      request.getSession().invalidate();
      response.sendRedirect("/");
    }
  }
}
