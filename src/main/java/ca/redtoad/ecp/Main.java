package ca.redtoad.ecp;

import java.nio.charset.StandardCharsets;

import ca.redtoad.sp.SAMLUtil;
import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import org.apache.http.HttpHeaders;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.bouncycastle.util.encoders.Base64;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.api.ContentResponse;
import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.http.HttpMethod;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.liberty.paos.Request;
import org.opensaml.soap.soap11.Envelope;
import org.slf4j.LoggerFactory;

public class Main
{
  private static final org.slf4j.Logger log = LoggerFactory.getLogger(Main.class);

  public static void main(String[] args) throws Exception {
    Logger root = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
    root.setLevel(Level.INFO);
    SAMLUtil.initSAML();
    HttpClient httpClient = null;
    ContentResponse resourceRequestToServiceProvider;
    try {
      httpClient = new HttpClient();
      httpClient.start();

      // Initial request for secure resource
      resourceRequestToServiceProvider = httpClient.newRequest("http://localhost:8081/secure")
          .method(HttpMethod.GET)
          .header(SAMLUtil.ECP_ACCEPT_HEADER_NAME, SAMLUtil.ECP_ACCEPT_HEADER_VALUE)
          .header(SAMLUtil.ECP_PAOS_HEADER_NAME,
              SAMLUtil.ECP_PAOS_HEADER_BASE_VALUE + "," + SAMLUtil.ECP_PAOS_HEADER_WANT_AUTHN_REQUEST_SIGNED_OPTION)
          .send();
    }
    finally {
      if (httpClient != null) {
        httpClient.stop();
      }
    }

    // Service Provider replies with authentication request for Identity Provider
    log.info("Http Status " + resourceRequestToServiceProvider.getStatus());
    log.info(resourceRequestToServiceProvider.getContentAsString());
    Envelope envelopeFromServiceProvider =
        (Envelope) SAMLUtil.unmarshall(resourceRequestToServiceProvider.getContentAsString());
    String assertionConsumerServiceUrlFromServiceProvider = null;
    for (XMLObject xmlObject : envelopeFromServiceProvider.getHeader().getUnknownXMLObjects()) {
      if (xmlObject instanceof Request) {
        Request request = (Request) xmlObject;
        assertionConsumerServiceUrlFromServiceProvider = request.getResponseConsumerURL();
      }
    }

    // Send the Service Provider's authentication request to the Identity Provider along with basic auth
    Envelope envelopeToIdentityProvider =
        SAMLUtil.detachBodyUnknownXMLObjectsIntoNewEnvelope(envelopeFromServiceProvider);
    HttpPost httpPost = new HttpPost(SAMLUtil.getIdentityProviderSingleSignOnServiceSOAPDestination());
    // Set basic authentication
    httpPost.setHeader(HttpHeaders.AUTHORIZATION, "Basic " +
        new String(Base64.encode("admin:admin123".getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8));
    SAMLUtil.encodeClientSOAPRequest(envelopeToIdentityProvider, httpPost);
    CloseableHttpResponse response = HttpClients.createDefault().execute(httpPost);

    // Identity Provider replies with authentication Response for Service Provider
    log.info(response.getStatusLine().toString());
    String content = SAMLUtil.toString(response.getEntity().getContent());
    log.info(content);
    Envelope envelopeFromIdentityProvider = (Envelope) SAMLUtil.unmarshall(content);
    String assertionConsumerServiceUrlFromIdentityProvider = null;
    for (XMLObject xmlObject : envelopeFromIdentityProvider.getHeader().getUnknownXMLObjects()) {
      if (xmlObject instanceof org.opensaml.saml.saml2.ecp.Response) {
        org.opensaml.saml.saml2.ecp.Response ecpResponse = (org.opensaml.saml.saml2.ecp.Response) xmlObject;
        assertionConsumerServiceUrlFromIdentityProvider = ecpResponse.getAssertionConsumerServiceURL();
        if (assertionConsumerServiceUrlFromServiceProvider != null &&
            !assertionConsumerServiceUrlFromServiceProvider.equals(assertionConsumerServiceUrlFromIdentityProvider)) {
          // Should "generate a SOAP fault response to the service provider" but just doing this instead for simplicity
          throw new RuntimeException(
              "Assertion consumer service url mismatch between Service Provider and Identity Provider");
        }
        break;
      }
    }

    // Send authentication Response to Service Provider
    Envelope envelopeToServiceProvider =
        SAMLUtil.detachBodyUnknownXMLObjectsIntoNewEnvelope(envelopeFromIdentityProvider);
    httpPost = new HttpPost(assertionConsumerServiceUrlFromServiceProvider !=
        null ? assertionConsumerServiceUrlFromServiceProvider : assertionConsumerServiceUrlFromIdentityProvider);
    // Reuse original session id which has the gotoURL set
    httpPost.setHeader(HttpHeader.COOKIE.asString(),
        resourceRequestToServiceProvider.getHeaders().get(HttpHeader.SET_COOKIE));
    httpPost.setHeader(HttpHeader.CONTENT_TYPE.asString(), SAMLUtil.ECP_ACCEPT_HEADER_VALUE);
    SAMLUtil.encodeClientSOAPRequest(envelopeToServiceProvider, httpPost);

    // Service Provider replies by granting/denying access to resource via a redirect
    response = HttpClientBuilder.create().build().execute(httpPost);
    HttpGet httpGet = new HttpGet(response.getHeaders("Location")[0].getValue());
    httpGet.setHeader(HttpHeader.COOKIE.asString(),
        resourceRequestToServiceProvider.getHeaders().get(HttpHeader.SET_COOKIE));
    response = HttpClientBuilder.create().build().execute(httpGet);
    log.info(response.getStatusLine().toString());
    content = SAMLUtil.toString(response.getEntity().getContent());
    log.info(content);
  }
}
