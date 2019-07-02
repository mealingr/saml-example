package ca.redtoad.sp;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import javax.security.auth.Subject;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.liberty.binding.decoding.HTTPPAOS11Decoder;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CallbackECP
    extends HttpServlet
{
  private static final Logger log = LoggerFactory.getLogger(CallbackECP.class);
  
  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
    HTTPPAOS11Decoder decoder = new HTTPPAOS11Decoder();
    decoder.setHttpServletRequest(request);
    try {
      decoder.initialize();
      decoder.decode();
    }
    catch (Exception e) {
      throw new RuntimeException(e);
    }
    MessageContext messageContext = decoder.getMessageContext();
    Response responseFromIdentityProvider = (Response) messageContext.getMessage();
    Assertion assertion = SAMLUtil.getAssertion(responseFromIdentityProvider, SAMLUtil.getServiceProviderCredential());
    SAMLUtil.verifySignature(assertion, Credential.getIdentityProviderCredential());

    String nameID = assertion.getSubject().getNameID().getValue();
    log.info(nameID);
    Map<String, List<String>> attributes = SAMLUtil.getAttributeValues(assertion);
    log.info(attributes.toString());
    UserPrincipal userPrincipal = new UserPrincipal(nameID, attributes);
    Subject subject = new Subject();
    subject.getPrincipals().add(userPrincipal);
    request.getSession().setAttribute(CallbackLogin.AUTHENTICATED_USER, userPrincipal);

    response.sendRedirect((String) request.getSession().getAttribute(CallbackLogin.GOTO_URL_ATTRIBUTE_NAME));
  }
}
