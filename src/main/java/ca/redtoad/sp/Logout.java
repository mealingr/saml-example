package ca.redtoad.sp;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Logout
    extends HttpServlet
{
  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response) {
    String destination = SAMLUtil.getIdentityProviderSingleLogoutServiceRedirectDestination();
    SAMLUtil.sendLogoutRequestViaPost(response, SAMLUtil.buildLogoutRequest(destination));
    // SAMLUtil.sendLogoutRequestViaRedirect(response, SAMLUtil.buildLogoutRequest(destination));
    // If we just want to logout locally then we would instead just call
    // request.getSession().invalidate();
  }
}
