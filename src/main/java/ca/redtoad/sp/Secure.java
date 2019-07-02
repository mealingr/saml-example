package ca.redtoad.sp;

import java.io.IOException;
import java.util.List;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.soap.soap11.Envelope;

public class Secure
    extends HttpServlet
{
  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    UserPrincipal userPrincipal = (UserPrincipal) request.getSession().getAttribute(CallbackLogin.AUTHENTICATED_USER);
    if (userPrincipal != null) {
      response.setContentType("text/html");
      response.setStatus(HttpServletResponse.SC_OK);
      response.getWriter()
          .printf("<html><p>Hello %s from secure! <a href='/logout'>Logout</a></p><p>Your attributes are %s</p></html>",
              userPrincipal.getName(), userPrincipal.getAttributes());
    }
    else {
      if (SAMLUtil.isPAOS(request)) {
        List<String> paosOptions = SAMLUtil.getPAOSOptions(request);
        Envelope envelope =
            SAMLUtil.buildAuthnRequestEnvelope(SAMLUtil.getIdentityProviderSingleSignOnServiceSOAPDestination(), paosOptions);
        request.getSession().setAttribute(CallbackLogin.GOTO_URL_ATTRIBUTE_NAME, request.getRequestURL().toString());
        SAMLUtil.sendEnvelopeViaPAOS(response, envelope);
      }
      else {
        request.getSession().setAttribute(CallbackLogin.GOTO_URL_ATTRIBUTE_NAME, request.getRequestURL().toString());
        RequestDispatcher dispatcher = getServletContext().getRequestDispatcher("/login");
        dispatcher.forward(request, response);
      }
    }
  }
}
