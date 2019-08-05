package ca.redtoad.ecp;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import ca.redtoad.sp.WebSecurityConfig;
import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.http.HttpHeaders;
import org.bouncycastle.util.encoders.Base64;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.api.ContentResponse;
import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.http.HttpMethod;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.ws.soap.client.BasicSOAPMessageContext;
import org.opensaml.ws.soap.client.SOAPClientException;
import org.opensaml.ws.soap.client.SOAPMessageContext;
import org.opensaml.ws.soap.client.http.HttpSOAPClient;
import org.opensaml.ws.soap.client.http.HttpSOAPRequestParameters;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.parse.BasicParserPool;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

public class Main
{
  private static final org.slf4j.Logger log = LoggerFactory.getLogger(Main.class);

  public static void main(String[] args) throws Exception {
    DefaultBootstrap.bootstrap();
    Logger root = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
    root.setLevel(Level.INFO);
    HttpClient httpClient = null;
    ContentResponse resourceRequestToServiceProvider;
    try {
      httpClient = new HttpClient();
      httpClient.start();

      // Initial request for secure resource
      resourceRequestToServiceProvider = httpClient.newRequest("http://localhost:8081/secure")
          .method(HttpMethod.GET)
          .header(WebSecurityConfig.ECP_ACCEPT_HEADER_NAME, WebSecurityConfig.ECP_ACCEPT_HEADER_VALUE)
          .header(WebSecurityConfig.ECP_PAOS_HEADER_NAME,
              WebSecurityConfig.ECP_PAOS_HEADER_BASE_VALUE + "," +
                  WebSecurityConfig.ECP_PAOS_HEADER_WANT_AUTHN_REQUEST_SIGNED_OPTION)
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
    BasicParserPool basicParserPool = new BasicParserPool();
    basicParserPool.setNamespaceAware(true);
    Element element = basicParserPool.parse(new ByteArrayInputStream(resourceRequestToServiceProvider.getContent()))
        .getDocumentElement();
    UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
    Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
    Envelope envelopeFromServiceProvider = (Envelope) unmarshaller.unmarshall(element);

    Envelope envelopeToIdentityProvider =
        WebSecurityConfig.detachBodyUnknownXMLObjectsIntoNewEnvelope(envelopeFromServiceProvider);
    HttpSOAPClient httpSOAPClient = new HttpSOAPClient(new org.apache.commons.httpclient.HttpClient(), basicParserPool)
    {
      @Override
      protected PostMethod createPostMethod(String endpoint, HttpSOAPRequestParameters requestParams, Envelope message)
          throws SOAPClientException
      {
        PostMethod postMethod = super.createPostMethod(endpoint, requestParams, message);
        // Set basic authentication
        postMethod.setRequestHeader(HttpHeaders.AUTHORIZATION, "Basic " +
            new String(Base64.encode("test:test".getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8));
        return postMethod;
      }
    };
    BasicSOAPMessageContext soapContext = new BasicSOAPMessageContext();
    soapContext.setOutboundMessage(envelopeToIdentityProvider);
    httpSOAPClient.send("http://localhost:8080/auth/realms/master/protocol/saml", soapContext);
    Envelope envelopeFromIdentityProvider = (Envelope) soapContext.getInboundMessage();
    log.info(envelopeFromIdentityProvider.toString());

    // Send authentication Response to Service Provider
    Envelope envelopeToServiceProvider =
        WebSecurityConfig.detachBodyUnknownXMLObjectsIntoNewEnvelope(envelopeFromIdentityProvider);
    org.apache.commons.httpclient.HttpClient client = new org.apache.commons.httpclient.HttpClient();
    httpSOAPClient = new HttpSOAPClient(client, basicParserPool)
    {
      @Override
      protected PostMethod createPostMethod(String endpoint, HttpSOAPRequestParameters requestParams, Envelope message)
          throws SOAPClientException
      {
        PostMethod postMethod = super.createPostMethod(endpoint, requestParams, message);
        // Set cookie
        postMethod.setRequestHeader(HttpHeader.COOKIE.asString(),
            resourceRequestToServiceProvider.getHeaders().get(HttpHeader.SET_COOKIE));
        postMethod.setRequestHeader(HttpHeader.CONTENT_TYPE.asString(), WebSecurityConfig.ECP_ACCEPT_HEADER_VALUE);
        return postMethod;
      }

      @Override
      public void send(String endpoint, SOAPMessageContext messageContext) throws SOAPClientException {
        PostMethod post = null;
        GetMethod get = null;
        try {
          post = this.createPostMethod(endpoint, (HttpSOAPRequestParameters) messageContext.getSOAPRequestParameters(),
              (Envelope) messageContext.getOutboundMessage());
          int result = client.executeMethod(post);
          if (result == 301 || result == 302) {
            String location = post.getResponseHeader("Location").getValue();
            get = new GetMethod(location);
            get.setRequestHeader(HttpHeader.COOKIE.asString(),
                resourceRequestToServiceProvider.getHeaders().get(HttpHeader.SET_COOKIE));
            result = client.executeMethod(get);
          }
          if (result == 200) {
            log.info(get.getResponseBodyAsString());
          }
        }
        catch (IOException ex) {
          ex.printStackTrace();
        }
        finally {
          if (post != null) {
            post.releaseConnection();
          }
          if (get != null) {
            get.releaseConnection();
          }
        }
      }
    };
    soapContext = new BasicSOAPMessageContext();
    soapContext.setOutboundMessage(envelopeToServiceProvider);
    httpSOAPClient.send("http://localhost:8081/callback/login", soapContext);
  }
}
