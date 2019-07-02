package ca.redtoad.sp;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import javax.security.auth.Subject;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.util.encoders.Base64;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CallbackLogin
    extends HttpServlet
{
  private static final Logger log = LoggerFactory.getLogger(CallbackLogin.class);

  static final String GOTO_URL_ATTRIBUTE_NAME = "gotoURL";

  static final String AUTHENTICATED_USER = "authenticated_user";

  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
    String samlResponse = request.getParameter("SAMLResponse");
    if (samlResponse == null) {
      return;
    }
    samlResponse = new String(Base64.decode(samlResponse), StandardCharsets.UTF_8);
    Assertion assertion =
        SAMLUtil.getAssertion((Response) SAMLUtil.unmarshall(samlResponse), Credential.getServiceProviderCredential());
    SAMLUtil.verifySignature(assertion, Credential.getIdentityProviderCredential());

    String nameID = assertion.getSubject().getNameID().getValue();
    log.info(nameID);
    Map<String, List<String>> attributes = SAMLUtil.getAttributeValues(assertion);
    log.info(attributes.toString());
    UserPrincipal userPrincipal = new UserPrincipal(nameID, attributes);
    Subject subject = new Subject();
    subject.getPrincipals().add(userPrincipal);
    request.getSession().setAttribute(AUTHENTICATED_USER, userPrincipal);

    response.sendRedirect((String) request.getSession().getAttribute(GOTO_URL_ATTRIBUTE_NAME));
  }
}
