package ca.redtoad.sp;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.Criterion;
import net.shibboleth.utilities.java.support.security.RandomIdentifierGenerationStrategy;
import org.apache.http.HttpRequest;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader;
import org.joda.time.DateTime;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.impl.XSAnyImpl;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.liberty.paos.impl.RequestMarshaller;
import org.opensaml.liberty.paos.impl.RequestUnmarshaller;
import org.opensaml.liberty.paos.impl.ResponseMarshaller;
import org.opensaml.liberty.paos.impl.ResponseUnmarshaller;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.common.binding.EndpointResolver;
import org.opensaml.saml.common.binding.impl.DefaultEndpointResolver;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.criterion.BindingCriterion;
import org.opensaml.saml.criterion.EndpointCriterion;
import org.opensaml.saml.criterion.EntityRoleCriterion;
import org.opensaml.saml.criterion.RoleDescriptorCriterion;
import org.opensaml.saml.metadata.resolver.impl.DOMMetadataResolver;
import org.opensaml.saml.metadata.resolver.impl.PredicateRoleDescriptorResolver;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPPostEncoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPRedirectDeflateEncoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPSOAP11Encoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HttpClientRequestSOAP11Encoder;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.IDPEntry;
import org.opensaml.saml.saml2.core.IDPList;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml.saml2.core.impl.IDPEntryBuilder;
import org.opensaml.saml.saml2.core.impl.IDPListBuilder;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.LogoutRequestBuilder;
import org.opensaml.saml.saml2.core.impl.LogoutResponseBuilder;
import org.opensaml.saml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.saml.saml2.core.impl.RequestedAuthnContextBuilder;
import org.opensaml.saml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml.saml2.ecp.Request;
import org.opensaml.saml.saml2.ecp.impl.RequestBuilder;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.Endpoint;
import org.opensaml.saml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.NameIDFormat;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml.saml2.metadata.impl.AssertionConsumerServiceBuilder;
import org.opensaml.saml.saml2.metadata.impl.EntitiesDescriptorBuilder;
import org.opensaml.saml.saml2.metadata.impl.EntityDescriptorBuilder;
import org.opensaml.saml.saml2.metadata.impl.KeyDescriptorBuilder;
import org.opensaml.saml.saml2.metadata.impl.NameIDFormatBuilder;
import org.opensaml.saml.saml2.metadata.impl.SPSSODescriptorBuilder;
import org.opensaml.saml.saml2.metadata.impl.SingleLogoutServiceBuilder;
import org.opensaml.saml.saml2.metadata.impl.SingleSignOnServiceBuilder;
import org.opensaml.saml.security.impl.MetadataCredentialResolver;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.credential.impl.KeyStoreCredentialResolver;
import org.opensaml.soap.messaging.context.SOAP11Context;
import org.opensaml.soap.soap11.Body;
import org.opensaml.soap.soap11.Envelope;
import org.opensaml.soap.soap11.Header;
import org.opensaml.soap.soap11.impl.BodyBuilder;
import org.opensaml.soap.soap11.impl.EnvelopeBuilder;
import org.opensaml.soap.soap11.impl.HeaderBuilder;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.config.impl.JavaCryptoValidationInitializer;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.KeyInfoGeneratorManager;
import org.opensaml.xmlsec.keyinfo.NamedKeyInfoGeneratorManager;
import org.opensaml.xmlsec.keyinfo.impl.BasicKeyInfoGeneratorFactory;
import org.opensaml.xmlsec.keyinfo.impl.BasicProviderKeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.keyinfo.impl.provider.InlineX509DataProvider;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.impl.SignatureBuilder;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.opensaml.xmlsec.signature.support.Signer;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

public class SAMLUtil
{
  private static org.slf4j.Logger log = LoggerFactory.getLogger(SAMLUtil.class);

  private static final RandomIdentifierGenerationStrategy RANDOM_IDENTIFIER_GENERATION_STRATEGY =
      new RandomIdentifierGenerationStrategy();

  public static final String SERVICE_PROVIDER_ENTITY_ID = "sp_opensaml_entity_id";

  public static final String SERVICE_PROVIDER_ASSERTION_CONSUMER_SERVICE_URL = "http://localhost:8081/callback/login";

  public static final String SERVICE_PROVIDER_SINGLE_LOGOUT_SERVICE_URL = "http://localhost:8081/callback/logout";

  public static final String SERVICE_PROVIDER_ECP_ASSERTION_CONSUMER_SERVICE_URL = "http://localhost:8081/callback/ecp";

  public static final String ECP_ACCEPT_HEADER_NAME = "Accept";

  public static final String ECP_ACCEPT_HEADER_VALUE = "application/vnd.paos+xml";

  public static final String ECP_PAOS_HEADER_NAME = "PAOS";

  public static final String ECP_PAOS_HEADER_BASE_VALUE =
      "ver='urn:liberty:paos:2003-08';'urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp'";

  public static final String ECP_PAOS_HEADER_WANT_AUTHN_REQUEST_SIGNED_OPTION =
      "'urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp:2.0:WantAuthnRequestsSigned'";

  public static void initSAML() throws InitializationException {
    // OpenSAML uses JCE for cryptographic functionality, the Bouncy Castle implementation is recommended, check for it
    JavaCryptoValidationInitializer javaCryptoValidationInitializer = new JavaCryptoValidationInitializer();
    javaCryptoValidationInitializer.init();
    for (Provider jceProvider : Security.getProviders()) {
      log.info(jceProvider.getInfo());
    }
    // Load OpenSAML default configuration files
    InitializationService.initialize();
    // Register PAOS request/response (un)marshaller
    XMLObjectProviderRegistrySupport.registerObjectProvider(org.opensaml.liberty.paos.Request.DEFAULT_ELEMENT_NAME,
        new org.opensaml.liberty.paos.impl.RequestBuilder(), new RequestMarshaller(), new RequestUnmarshaller());
    XMLObjectProviderRegistrySupport.registerObjectProvider(org.opensaml.liberty.paos.Response.DEFAULT_ELEMENT_NAME,
        new org.opensaml.liberty.paos.impl.ResponseBuilder(), new ResponseMarshaller(), new ResponseUnmarshaller());
  }

  public static XMLObject unmarshall(String xml) {
    try {
      return XMLObjectSupport.unmarshallFromInputStream(XMLObjectProviderRegistrySupport.getParserPool(),
          new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
    }
    catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public static Map<String, List<String>> getAttributeValues(Assertion assertion) {
    Map<String, List<String>> attributeValues = new HashMap<>();
    for (AttributeStatement attributeStatement : assertion.getAttributeStatements()) {
      for (Attribute attribute : attributeStatement.getAttributes()) {
        attributeValues.putIfAbsent(attribute.getName(), new ArrayList<>());
        for (XMLObject attributeValue : attribute.getAttributeValues()) {
          attributeValues.get(attribute.getName()).add(getAttributeValue(attributeValue));
        }
      }
    }
    return attributeValues;
  }

  public static String getAttributeValue(XMLObject attributeValue) {
    return attributeValue == null ? null : attributeValue instanceof XSString ? getStringAttributeValue(
        (XSString) attributeValue) : attributeValue instanceof XSAnyImpl ? getAnyAttributeValue(
        (XSAnyImpl) attributeValue) : attributeValue.toString();
  }

  public static String getStringAttributeValue(XSString attributeValue) {
    return attributeValue.getValue();
  }

  public static String getAnyAttributeValue(XSAnyImpl attributeValue) {
    return attributeValue.getTextContent();
  }

  public static Assertion getAssertion(Response response, org.opensaml.security.credential.Credential credential) {
    if (!response.getAssertions().isEmpty()) {
      return response.getAssertions().get(0);
    }
    if (!response.getEncryptedAssertions().isEmpty()) {
      return getAssertion(response.getEncryptedAssertions().get(0), credential);
    }
    throw new RuntimeException("Failed to get the assetion.");
  }

  public static Assertion getAssertion(
      EncryptedAssertion encryptedAssertion,
      org.opensaml.security.credential.Credential credential)
  {
    try {
      Decrypter decrypter =
          new Decrypter(null, new StaticKeyInfoCredentialResolver(credential), new InlineEncryptedKeyResolver());
      decrypter.setRootInNewDocument(true);
      return decrypter.decrypt(encryptedAssertion);
    }
    catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public static void verifySignature(SignableSAMLObject signableSAMLObject, Credential credential) {
    try {
      SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
      profileValidator.validate(signableSAMLObject.getSignature());
      SignatureValidator.validate(signableSAMLObject.getSignature(), credential);
    }
    catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public static Credential getKeyStoreCredential(InputStream inputStream, String password, String entityId) {
    try {
      KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
      keystore.load(inputStream, password.toCharArray());
      inputStream.close();
      Map<String, String> passwordMap = new HashMap<String, String>();
      passwordMap.put(entityId, password);
      KeyStoreCredentialResolver resolver = new KeyStoreCredentialResolver(keystore, passwordMap);
      Criterion criterion = new EntityIdCriterion(entityId);
      CriteriaSet criteriaSet = new CriteriaSet();
      criteriaSet.add(criterion);
      return resolver.resolveSingle(criteriaSet);
    }
    catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public static Credential getServiceProviderCredential() {
    return getKeyStoreCredential(SAMLUtil.class.getClassLoader().getResourceAsStream("trust.keystore"), "changeit",
        "saml");
  }

  public static Credential getMetadataCredential(EntityDescriptor metadata) {
    try {
      DOMMetadataResolver domMetadataResolver = new DOMMetadataResolver(metadata.getDOM());
      domMetadataResolver.setId(UUID.randomUUID().toString());
      domMetadataResolver.initialize();
      MetadataCredentialResolver metadataCredentialResolver = new MetadataCredentialResolver();
      BasicProviderKeyInfoCredentialResolver basicProviderKeyInfoCredentialResolver =
          new BasicProviderKeyInfoCredentialResolver(Collections.singletonList(new InlineX509DataProvider()));
      metadataCredentialResolver.setKeyInfoCredentialResolver(basicProviderKeyInfoCredentialResolver);
      PredicateRoleDescriptorResolver predicateRoleDescriptorResolver =
          new PredicateRoleDescriptorResolver(domMetadataResolver);
      predicateRoleDescriptorResolver.initialize();
      metadataCredentialResolver.setRoleDescriptorResolver(predicateRoleDescriptorResolver);
      metadataCredentialResolver.initialize();
      CriteriaSet criteriaSet = new CriteriaSet();
      criteriaSet.add(new EntityIdCriterion(metadata.getEntityID()));
      criteriaSet.add(new EntityRoleCriterion(metadata.getRoleDescriptors().get(0).getElementQName()));
      return metadataCredentialResolver.resolveSingle(criteriaSet);
    }
    catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public static String getIdentityProviderSingleLogoutServiceRedirectDestination() {
    try {
      EndpointResolver<SingleLogoutService> endpointResolver = new DefaultEndpointResolver();
      CriteriaSet criteriaSet = new CriteriaSet();
      criteriaSet.add(new RoleDescriptorCriterion(getIdentityProviderMetadata().getRoleDescriptors().get(0)));
      criteriaSet.add(new EndpointCriterion<>(new SingleLogoutServiceBuilder().buildObject()));
      criteriaSet
          .add(new BindingCriterion(Collections.singletonList("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")));
      return endpointResolver.resolveSingle(criteriaSet).getLocation();
    }
    catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public static String getIdentityProviderSingleSignOnServiceRedirectDestination() {
    try {
      EndpointResolver<SingleSignOnService> endpointResolver = new DefaultEndpointResolver();
      CriteriaSet criteriaSet = new CriteriaSet();
      criteriaSet.add(new RoleDescriptorCriterion(getIdentityProviderMetadata().getRoleDescriptors().get(0)));
      criteriaSet.add(new EndpointCriterion<>(new SingleSignOnServiceBuilder().buildObject()));
      criteriaSet
          .add(new BindingCriterion(Collections.singletonList("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")));
      return endpointResolver.resolveSingle(criteriaSet).getLocation();
    }
    catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public static String getIdentityProviderSingleSignOnServiceSOAPDestination() {
    try {
      EndpointResolver<SingleSignOnService> endpointResolver = new DefaultEndpointResolver();
      CriteriaSet criteriaSet = new CriteriaSet();
      criteriaSet.add(new RoleDescriptorCriterion(getIdentityProviderMetadata().getRoleDescriptors().get(0)));
      criteriaSet.add(new EndpointCriterion<>(new SingleSignOnServiceBuilder().buildObject()));
      criteriaSet
          .add(new BindingCriterion(Collections.singletonList("urn:oasis:names:tc:SAML:2.0:bindings:SOAP")));
      return endpointResolver.resolveSingle(criteriaSet).getLocation();
    }
    catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public static EntityDescriptor getMetadata(InputStream inputStream) {
    XMLObject xmlObject = unmarshall(toString(inputStream));
    if (xmlObject instanceof EntitiesDescriptor) {
      EntitiesDescriptor entitiesDescriptor = (EntitiesDescriptor) xmlObject;
      return entitiesDescriptor.getEntityDescriptors().get(0);
    }
    else if (xmlObject instanceof EntityDescriptor) {
      return (EntityDescriptor) xmlObject;
    }
    throw new RuntimeException("Couldn't get the metadata from " + xmlObject.getClass());
  }

  public static EntityDescriptor getIdentityProviderMetadata() {
    return getMetadata(SAMLUtil.class.getClassLoader().getResourceAsStream("cs-auth-proxy-idp.xml"));
  }

  public static Credential getIdentityProviderCredential() {
    return getMetadataCredential(getIdentityProviderMetadata());
  }

  public static String toString(InputStream inputStream) {
    return new BufferedReader(new InputStreamReader(inputStream)).lines()
        .collect(Collectors.joining(System.lineSeparator()));
  }

  public static String toString(XMLObject object) {
    try {
      Element element;
      if (object instanceof SignableSAMLObject && ((SignableSAMLObject) object).isSigned() && object.getDOM() != null) {
        element = object.getDOM();
      }
      else {
        Marshaller out = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(object);
        out.marshall(object);
        element = object.getDOM();
      }
      Transformer transformer = TransformerFactory.newInstance().newTransformer();
      transformer.setOutputProperty(OutputKeys.INDENT, "yes");
      StreamResult result = new StreamResult(new StringWriter());
      DOMSource source = new DOMSource(element);
      transformer.transform(source, result);
      return result.getWriter().toString();
    }
    catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public static AuthnRequest buildAuthnRequest(String destination) {
    AuthnRequest authnRequest = new AuthnRequestBuilder().buildObject();
    authnRequest.setIssueInstant(new DateTime());
    authnRequest.setDestination(destination);
    authnRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
    // authnRequest.setProtocolBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
    authnRequest.setAssertionConsumerServiceURL(SERVICE_PROVIDER_ASSERTION_CONSUMER_SERVICE_URL);
    authnRequest.setID(SAMLUtil.RANDOM_IDENTIFIER_GENERATION_STRATEGY.generateIdentifier());
    Issuer issuer = new IssuerBuilder().buildObject();
    issuer.setValue(SERVICE_PROVIDER_ENTITY_ID);
    authnRequest.setIssuer(issuer);
    NameIDPolicy nameIDPolicy = new NameIDPolicyBuilder().buildObject();
    nameIDPolicy.setAllowCreate(true);
    nameIDPolicy.setFormat(NameIDType.TRANSIENT);
    authnRequest.setNameIDPolicy(nameIDPolicy);
    RequestedAuthnContext requestedAuthnContext = new RequestedAuthnContextBuilder().buildObject();
    requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.MINIMUM);
    AuthnContextClassRef authnContextClassRef = new AuthnContextClassRefBuilder().buildObject();
    authnContextClassRef.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);
    requestedAuthnContext.getAuthnContextClassRefs().add(authnContextClassRef);
    authnRequest.setRequestedAuthnContext(requestedAuthnContext);
    authnRequest.setSignature(getSignature(getKeyInfo(getServiceProviderCredential())));
    return authnRequest;
  }

  public static LogoutResponse buildLogoutResponse(LogoutRequest logoutRequest, String destination) {
    LogoutResponse logoutResponse = new LogoutResponseBuilder().buildObject();
    logoutResponse.setID(SAMLUtil.RANDOM_IDENTIFIER_GENERATION_STRATEGY.generateIdentifier());
    logoutResponse.setIssueInstant(new DateTime());
    logoutResponse.setDestination(destination);
    Issuer issuer = new IssuerBuilder().buildObject();
    issuer.setValue(SERVICE_PROVIDER_ENTITY_ID);
    logoutResponse.setIssuer(issuer);
    logoutResponse.setInResponseTo(logoutRequest.getID());
    StatusBuilder statusBuilder = new StatusBuilder();
    Status status = statusBuilder.buildObject();
    StatusCodeBuilder statusCodeBuilder = new StatusCodeBuilder();
    StatusCode statusCode = statusCodeBuilder.buildObject();
    statusCode.setValue(StatusCode.SUCCESS);
    status.setStatusCode(statusCode);
    logoutResponse.setStatus(status);
    logoutResponse.setSignature(getSignature(getKeyInfo(getServiceProviderCredential())));
    return logoutResponse;
  }

  public static LogoutRequest buildLogoutRequest(String destination) {
    LogoutRequest logoutRequest = new LogoutRequestBuilder().buildObject();
    logoutRequest.setID(SAMLUtil.RANDOM_IDENTIFIER_GENERATION_STRATEGY.generateIdentifier());
    logoutRequest.setIssueInstant(new DateTime());
    logoutRequest.setDestination(destination);
    Issuer issuer = new IssuerBuilder().buildObject();
    issuer.setValue(SERVICE_PROVIDER_ENTITY_ID);
    logoutRequest.setIssuer(issuer);
    logoutRequest.setSignature(getSignature(getKeyInfo(getServiceProviderCredential())));
    return logoutRequest;
  }

  public static EntitiesDescriptor buildServiceProviderMetdata() {
    EntitiesDescriptor entitiesDescriptor = new EntitiesDescriptorBuilder().buildObject();
    EntityDescriptor entityDescriptor = new EntityDescriptorBuilder().buildObject();
    entityDescriptor.setEntityID(SERVICE_PROVIDER_ENTITY_ID);
    SPSSODescriptor descriptor = new SPSSODescriptorBuilder().buildObject();
    descriptor.addSupportedProtocol("urn:oasis:names:tc:SAML:2.0:protocol");
    descriptor.setAuthnRequestsSigned(true);
    descriptor.setWantAssertionsSigned(true);
    KeyDescriptor signingKeyDescriptor = new KeyDescriptorBuilder().buildObject();
    signingKeyDescriptor.setUse(UsageType.SIGNING);
    signingKeyDescriptor.setKeyInfo(getKeyInfo(getServiceProviderCredential()));
    descriptor.getKeyDescriptors().add(signingKeyDescriptor);
    KeyDescriptor encryptionKeyDescriptor = new KeyDescriptorBuilder().buildObject();
    encryptionKeyDescriptor.setUse(UsageType.ENCRYPTION);
    encryptionKeyDescriptor.setKeyInfo(getKeyInfo(getServiceProviderCredential()));
    descriptor.getKeyDescriptors().add(encryptionKeyDescriptor);
    AssertionConsumerService assertionConsumerService = new AssertionConsumerServiceBuilder().buildObject();
    assertionConsumerService.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);
    // assertionConsumerService.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
    assertionConsumerService.setLocation(SERVICE_PROVIDER_ASSERTION_CONSUMER_SERVICE_URL);
    AssertionConsumerService ecpAssertionConsumerService = new AssertionConsumerServiceBuilder().buildObject();
    ecpAssertionConsumerService.setBinding(SAMLConstants.SAML2_PAOS_BINDING_URI);
    ecpAssertionConsumerService.setLocation(SERVICE_PROVIDER_ECP_ASSERTION_CONSUMER_SERVICE_URL);
    SingleLogoutService singleLogoutService = new SingleLogoutServiceBuilder().buildObject();
    singleLogoutService.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);
    // assertionConsumerService.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI); // Not implemented
    singleLogoutService.setLocation(SERVICE_PROVIDER_SINGLE_LOGOUT_SERVICE_URL);
    descriptor.getAssertionConsumerServices().add(assertionConsumerService);
    descriptor.getAssertionConsumerServices().add(ecpAssertionConsumerService);
    descriptor.getSingleLogoutServices().add(singleLogoutService);
    NameIDFormat nameIDFormat = new NameIDFormatBuilder().buildObject();
    nameIDFormat.setFormat(NameIDType.TRANSIENT);
    descriptor.getNameIDFormats().add(nameIDFormat);
    entityDescriptor.getRoleDescriptors().add(descriptor);
    entitiesDescriptor.getEntityDescriptors().add(entityDescriptor);
    return entitiesDescriptor;
  }

  public static KeyInfo getKeyInfo(Credential credential) {
    try {
      NamedKeyInfoGeneratorManager namedManager = new NamedKeyInfoGeneratorManager();
      namedManager.setUseDefaultManager(true);
      KeyInfoGeneratorManager defaultManager = namedManager.getDefaultManager();
      BasicKeyInfoGeneratorFactory basicFactory = new BasicKeyInfoGeneratorFactory();
      basicFactory.setEmitPublicKeyValue(true);
      basicFactory.setEmitPublicDEREncodedKeyValue(true);
      basicFactory.setEmitKeyNames(true);
      X509KeyInfoGeneratorFactory x509Factory = new X509KeyInfoGeneratorFactory();
      x509Factory.setEmitEntityCertificate(true);
      defaultManager.registerFactory(basicFactory);
      defaultManager.registerFactory(x509Factory);
      KeyInfoGenerator keyInfoGenerator = namedManager.getDefaultManager().getFactory(credential).newInstance();
      return keyInfoGenerator.generate(credential);
    }
    catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public static Signature getSignature(KeyInfo keyInfo) {
    Signature signature = new SignatureBuilder().buildObject();
    signature.setSigningCredential(ca.redtoad.sp.Credential.getServiceProviderCredential());
    signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
    signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
    signature.setKeyInfo(keyInfo);
    return signature;
  }

  public static void sendAuthnRequestViaRedirect(
      HttpServletResponse response,
      AuthnRequest authnRequest)
  {
    sendViaRedirect(response, authnRequest, new SingleSignOnServiceBuilder().buildObject(),
        authnRequest.getDestination());
  }

  public static void sendLogoutRequestViaRedirect(
      HttpServletResponse response,
      LogoutRequest message)
  {
    sendViaRedirect(response, message, new SingleLogoutServiceBuilder().buildObject(), message.getDestination());
  }

  public static void sendLogoutResponseViaRedirect(
      HttpServletResponse response,
      LogoutResponse message)
  {
    sendViaRedirect(response, message, new SingleLogoutServiceBuilder().buildObject(), message.getDestination());
  }

  public static void sendViaRedirect(
      HttpServletResponse response,
      SignableSAMLObject message,
      Endpoint endpoint,
      String location)
  {
    sign(message);
    MessageContext context = new MessageContext();
    context.setMessage(message);
    SAMLPeerEntityContext peerEntityContext = context.getSubcontext(SAMLPeerEntityContext.class, true);
    SAMLEndpointContext endpointContext = peerEntityContext.getSubcontext(SAMLEndpointContext.class, true);
    endpoint.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
    endpoint.setLocation(location);
    endpointContext.setEndpoint(endpoint);

    SecurityParametersContext securityParametersContext = context.getSubcontext(SecurityParametersContext.class, true);
    SignatureSigningParameters signatureSigningParameters = new SignatureSigningParameters();
    signatureSigningParameters.setSigningCredential(ca.redtoad.sp.Credential.getServiceProviderCredential());
    // keytool -genkey -keyalg RSA -alias saml -keypass changeit -keystore trust.keystore -storepass changeit
    // default when using the above
    signatureSigningParameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
    securityParametersContext.setSignatureSigningParameters(signatureSigningParameters);

    /*EncryptionParameters encryptionParameters = new EncryptionParameters();
    encryptionParameters.setKeyTransportEncryptionCredential(CREDENTIAL);
    encryptionParameters.setKeyTransportEncryptionAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
    securityParametersContext.setEncryptionParameters(encryptionParameters);*/

    HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();
    encoder.setMessageContext(context);
    encoder.setHttpServletResponse(response);

    try {
      encoder.initialize();
      encoder.encode();
    }
    catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public static void sendAuthnRequestViaPost(
      HttpServletResponse response,
      AuthnRequest authnRequest)
  {
    sendViaPost(response, authnRequest, new SingleSignOnServiceBuilder().buildObject(),
        authnRequest.getDestination());
  }

  public static void sendLogoutRequestViaPost(
      HttpServletResponse response,
      LogoutRequest message)
  {
    sendViaPost(response, message, new SingleLogoutServiceBuilder().buildObject(), message.getDestination());
  }

  public static void sendLogoutResponseViaPost(
      HttpServletResponse response,
      LogoutResponse message)
  {
    sendViaPost(response, message, new SingleLogoutServiceBuilder().buildObject(), message.getDestination());
  }

  public static void sendViaPost(
      HttpServletResponse response,
      SignableSAMLObject message,
      Endpoint endpoint,
      String location)
  {
    sign(message);
    MessageContext context = new MessageContext();
    context.setMessage(message);
    SAMLPeerEntityContext peerEntityContext = context.getSubcontext(SAMLPeerEntityContext.class, true);
    SAMLEndpointContext endpointContext = peerEntityContext.getSubcontext(SAMLEndpointContext.class, true);
    endpoint.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);
    endpoint.setLocation(location);
    endpointContext.setEndpoint(endpoint);

    HTTPPostEncoder encoder = new HTTPPostEncoder();
    VelocityEngine velocityEngine = new VelocityEngine();
    velocityEngine.setProperty(RuntimeConstants.RESOURCE_LOADER, "classpath");
    velocityEngine.setProperty("classpath.resource.loader.class", ClasspathResourceLoader.class.getName());
    velocityEngine.init();
    encoder.setVelocityEngine(velocityEngine);
    encoder.setVelocityTemplateId("saml2-post-binding.vm");
    encoder.setMessageContext(context);
    encoder.setHttpServletResponse(response);
    try {
      encoder.initialize();
      encoder.encode();
    }
    catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public static void sign(SignableSAMLObject signableSAMLObject) {
    try {
      XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(signableSAMLObject)
          .marshall(signableSAMLObject);
      Signer.signObject(signableSAMLObject.getSignature());
    }
    catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public static boolean isPAOS(HttpServletRequest request) {
    List<String> accepts = Collections.list(request.getHeaders("Accept"));
    if (!accepts.contains("application/vnd.paos+xml")) {
      return false;
    }
    String paos = request.getHeader("PAOS");
    String[] paosVersionAndServiceOptions = paos.split(";");
    if (!paosVersionAndServiceOptions[0].trim().matches("ver=(['\"])urn:liberty:paos:2003-08\\1")) {
      return false;
    }
    String[] paosServiceAndOptions = paosVersionAndServiceOptions[1].trim().split(",");
    if (!paosServiceAndOptions[0].trim().matches("(['\"])urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp\\1")) {
      return false;
    }
    return true;
  }

  public static List<String> getPAOSOptions(HttpServletRequest request) {
    return Arrays.stream(request.getHeader("PAOS").split(",")).map(String::trim).filter(s -> !s.startsWith("ver"))
        .collect(Collectors.toList());
  }

  public static AuthnRequest buildECPAuthnRequest(String destination, List<String> paosOptions) {
    AuthnRequest authnRequest = new AuthnRequestBuilder().buildObject();
    authnRequest.setIssueInstant(new DateTime());
    authnRequest.setDestination(destination);
    authnRequest.setProtocolBinding(SAMLConstants.SAML2_PAOS_BINDING_URI);
    authnRequest.setAssertionConsumerServiceURL(SERVICE_PROVIDER_ECP_ASSERTION_CONSUMER_SERVICE_URL);
    authnRequest.setID(SAMLUtil.RANDOM_IDENTIFIER_GENERATION_STRATEGY.generateIdentifier());
    Issuer issuer = new IssuerBuilder().buildObject();
    issuer.setValue(SERVICE_PROVIDER_ENTITY_ID);
    authnRequest.setIssuer(issuer);
    NameIDPolicy nameIDPolicy = new NameIDPolicyBuilder().buildObject();
    nameIDPolicy.setAllowCreate(true);
    nameIDPolicy.setFormat(NameIDType.TRANSIENT);
    authnRequest.setNameIDPolicy(nameIDPolicy);
    RequestedAuthnContext requestedAuthnContext = new RequestedAuthnContextBuilder().buildObject();
    requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.MINIMUM);
    AuthnContextClassRef authnContextClassRef = new AuthnContextClassRefBuilder().buildObject();
    authnContextClassRef.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);
    requestedAuthnContext.getAuthnContextClassRefs().add(authnContextClassRef);
    authnRequest.setRequestedAuthnContext(requestedAuthnContext);
    if (paosOptions.contains("'urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp:2.0:WantAuthnRequestsSigned'")) {
      authnRequest.setSignature(getSignature(getKeyInfo(getServiceProviderCredential())));
    }
    return authnRequest;
  }

  public static org.opensaml.liberty.paos.Request buildPAOSRequestHeader() {
    org.opensaml.liberty.paos.Request request = new org.opensaml.liberty.paos.impl.RequestBuilder().buildObject();
    request.setSOAP11MustUnderstand(true);
    request.setSOAP11Actor("http://schemas.xmlsoap.org/soap/actor/next");
    request.setService("urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp");
    request.setResponseConsumerURL(SERVICE_PROVIDER_ECP_ASSERTION_CONSUMER_SERVICE_URL);
    request.setMessageID(RANDOM_IDENTIFIER_GENERATION_STRATEGY.generateIdentifier());
    return request;
  }

  public static Request buildECPRequestHeader() {
    Request request = new RequestBuilder().buildObject();
    request.setSOAP11MustUnderstand(true);
    request.setSOAP11Actor("http://schemas.xmlsoap.org/soap/actor/next");
    request.setProviderName(SERVICE_PROVIDER_ENTITY_ID);
    request.setPassive(true);
    Issuer issuer = new IssuerBuilder().buildObject();
    issuer.setValue(SERVICE_PROVIDER_ENTITY_ID);
    request.setIssuer(issuer);
    IDPList idpList = new IDPListBuilder().buildObject();
    IDPEntry idpEntry = new IDPEntryBuilder().buildObject();
    idpEntry.setProviderID(getIdentityProviderMetadata().getEntityID());
    idpEntry.setName(getIdentityProviderMetadata().getEntityID());
    idpEntry.setLoc(getIdentityProviderSingleSignOnServiceSOAPDestination());
    idpList.getIDPEntrys().add(idpEntry);
    request.setIDPList(idpList);
    return request;
  }

  public static Envelope buildAuthnRequestEnvelope(String destination, List<String> paosOptions) {
    org.opensaml.liberty.paos.Request paosRequestHeader = buildPAOSRequestHeader();
    Request ecpRequestHeader = buildECPRequestHeader();
    AuthnRequest ecpAuthnRequest = buildECPAuthnRequest(destination, paosOptions);
    Envelope envelope = new EnvelopeBuilder().buildObject();
    Header header = new HeaderBuilder().buildObject();
    header.getUnknownXMLObjects().add(paosRequestHeader);
    header.getUnknownXMLObjects().add(ecpRequestHeader);
    envelope.setHeader(header);
    Body body = new BodyBuilder().buildObject();
    body.getUnknownXMLObjects().add(ecpAuthnRequest);
    envelope.setBody(body);
    return envelope;
  }

  public static Element marshall(XMLObject object) {
    MarshallerFactory MarshallerFactory = XMLObjectProviderRegistrySupport.getMarshallerFactory();
    Marshaller marshaller = MarshallerFactory.getMarshaller(object.getElementQName());
    try {
      return marshaller.marshall(object);
    }
    catch (MarshallingException e) {
      throw new RuntimeException(e);
    }
  }

  public static void sendEnvelopeViaPAOS(
      HttpServletResponse response,
      Envelope envelope)
  {
    AuthnRequest authnRequest = (AuthnRequest) envelope.getBody().getUnknownXMLObjects().get(0);
    sign(authnRequest);
    sendViaPAOS(response, envelope, new SingleSignOnServiceBuilder().buildObject(), authnRequest.getDestination());
  }

  public static void sendViaPAOS(
      HttpServletResponse response,
      Envelope envelope,
      Endpoint endpoint,
      String location)
  {
    /*ByteArrayOutputStream bos = new ByteArrayOutputStream();
    SerializeSupport.writeNode(SAMLUtil.marshall(envelope), bos);
    response.getWriter().write(new String(bos.toByteArray(), StandardCharsets.UTF_8));*/
    HTTPSOAP11Encoder encoder = new HTTPSOAP11Encoder();
    MessageContext context = new MessageContext();
    context.getSubcontext(SOAP11Context.class, true).setEnvelope(envelope);

    SAMLPeerEntityContext peerEntityContext = context.getSubcontext(SAMLPeerEntityContext.class, true);
    SAMLEndpointContext endpointContext = peerEntityContext.getSubcontext(SAMLEndpointContext.class, true);
    endpoint.setBinding(SAMLConstants.SAML2_PAOS_BINDING_URI);
    endpoint.setLocation(location);
    endpointContext.setEndpoint(endpoint);

    encoder.setMessageContext(context);
    encoder.setHttpServletResponse(response);
    try {
      encoder.initialize();
      encoder.encode();
    }
    catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  // Leaving this method here as a reminder, cloning like this can mess up the signature value (if one exists).
  // Instead it's better to .detach() the object if you can (or clone it properly somehow)
  private static XMLObject clone(XMLObject xmlObject) {
    return unmarshall(toString(xmlObject));
  }

  public static Envelope detachBodyUnknownXMLObjectsIntoNewEnvelope(Envelope envelope) {
    Envelope env = new EnvelopeBuilder().buildObject();
    Body body = new BodyBuilder().buildObject();
    for (XMLObject xmlObject : envelope.getBody().getUnknownXMLObjects()) {
      xmlObject.detach();
      body.getUnknownXMLObjects().add(xmlObject);
    }
    env.setBody(body);
    return env;
  }

  public static void encodeClientSOAPRequest(Envelope envelope, HttpRequest httpRequest) {
    HttpClientRequestSOAP11Encoder encoder = new HttpClientRequestSOAP11Encoder();
    MessageContext context = new MessageContext();
    Endpoint endpoint = new SingleSignOnServiceBuilder().buildObject();
    context.getSubcontext(SOAP11Context.class, true).setEnvelope(envelope);
    SAMLPeerEntityContext peerEntityContext = context.getSubcontext(SAMLPeerEntityContext.class, true);
    SAMLEndpointContext endpointContext = peerEntityContext.getSubcontext(SAMLEndpointContext.class, true);
    endpoint.setBinding(SAMLConstants.SAML2_PAOS_BINDING_URI);
    endpoint.setLocation(httpRequest.getRequestLine().getUri());
    endpointContext.setEndpoint(endpoint);
    encoder.setMessageContext(context);
    encoder.setHttpRequest(httpRequest);
    try {
      encoder.initialize();
      encoder.encode();
    }
    catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
