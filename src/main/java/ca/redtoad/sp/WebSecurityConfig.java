package ca.redtoad.sp;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Timer;
import java.util.stream.Collectors;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.ws.soap.soap11.Header;
import org.opensaml.ws.soap.soap11.impl.BodyBuilder;
import org.opensaml.ws.soap.soap11.impl.EnvelopeBuilder;
import org.opensaml.ws.soap.soap11.impl.HeaderBuilder;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.opensaml.xml.security.BasicSecurityConfiguration;
import org.opensaml.xml.signature.SignatureConstants;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLBootstrap;
import org.springframework.security.saml.SAMLDiscovery;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.SAMLLogoutFilter;
import org.springframework.security.saml.SAMLLogoutProcessingFilter;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.saml.SAMLWebSSOHoKProcessingFilter;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.security.saml.metadata.CachingMetadataManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;
import org.springframework.security.saml.metadata.MetadataDisplayFilter;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.springframework.security.saml.metadata.MetadataGeneratorFilter;
import org.springframework.security.saml.parser.ParserPoolHolder;
import org.springframework.security.saml.processor.HTTPArtifactBinding;
import org.springframework.security.saml.processor.HTTPPAOS11Binding;
import org.springframework.security.saml.processor.HTTPPostBinding;
import org.springframework.security.saml.processor.HTTPRedirectDeflateBinding;
import org.springframework.security.saml.processor.HTTPSOAP11Binding;
import org.springframework.security.saml.processor.SAMLBinding;
import org.springframework.security.saml.processor.SAMLProcessorImpl;
import org.springframework.security.saml.trust.httpclient.TLSProtocolConfigurer;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.saml.websso.ArtifactResolutionProfile;
import org.springframework.security.saml.websso.ArtifactResolutionProfileImpl;
import org.springframework.security.saml.websso.SingleLogoutProfile;
import org.springframework.security.saml.websso.SingleLogoutProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfile;
import org.springframework.security.saml.websso.WebSSOProfileConsumer;
import org.springframework.security.saml.websso.WebSSOProfileConsumerHoKImpl;
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl;
import org.springframework.security.saml.websso.WebSSOProfileECPImpl;
import org.springframework.security.saml.websso.WebSSOProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfileOptions;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true)
public class WebSecurityConfig
    extends WebSecurityConfigurerAdapter
    implements InitializingBean, DisposableBean
{
  static final String AUTHENTICATED_USER = "authenticated_user";

  public static final String ECP_ACCEPT_HEADER_NAME = "Accept";

  public static final String ECP_ACCEPT_HEADER_VALUE = "application/vnd.paos+xml";

  public static final String ECP_PAOS_HEADER_NAME = "PAOS";

  public static final String ECP_PAOS_HEADER_BASE_VALUE =
      "ver='urn:liberty:paos:2003-08';'urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp'";

  public static final String ECP_PAOS_HEADER_WANT_AUTHN_REQUEST_SIGNED_OPTION =
      "'urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp:2.0:WantAuthnRequestsSigned'";

  private Timer backgroundTaskTimer;

  private MultiThreadedHttpConnectionManager multiThreadedHttpConnectionManager;

  public void init() {
    this.backgroundTaskTimer = new Timer(true);
    this.multiThreadedHttpConnectionManager = new MultiThreadedHttpConnectionManager();
    BasicSecurityConfiguration config =
        (BasicSecurityConfiguration) org.opensaml.Configuration.getGlobalSecurityConfiguration();
    config.registerSignatureAlgorithmURI("RSA", SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
    config.setSignatureReferenceDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA256);
    config.setSignatureCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
  }

  public void shutdown() {
    this.backgroundTaskTimer.purge();
    this.backgroundTaskTimer.cancel();
    this.multiThreadedHttpConnectionManager.shutdown();
  }

  @Autowired
  private SAMLUserDetailsServiceImpl samlUserDetailsServiceImpl;

  // Initialization of the velocity engine
  @Bean
  public VelocityEngine velocityEngine() {
    return VelocityFactory.getEngine();
  }

  // XML parser pool needed for OpenSAML parsing
  @Bean(initMethod = "initialize")
  public StaticBasicParserPool parserPool() {
    return new StaticBasicParserPool();
  }

  @Bean(name = "parserPoolHolder")
  public ParserPoolHolder parserPoolHolder() {
    return new ParserPoolHolder();
  }

  // Bindings, encoders and decoders used for creating and parsing messages
  @Bean
  public HttpClient httpClient() {
    return new HttpClient(this.multiThreadedHttpConnectionManager);
  }

  // SAML Authentication Provider responsible for validating of received SAML
  // messages
  @Bean
  public SAMLAuthenticationProvider samlAuthenticationProvider() {
    SAMLAuthenticationProvider samlAuthenticationProvider = new SAMLAuthenticationProvider();
    samlAuthenticationProvider.setUserDetails(samlUserDetailsServiceImpl);
    samlAuthenticationProvider.setForcePrincipalAsString(false);
    return samlAuthenticationProvider;
  }

  // Provider of default SAML Context
  @Bean
  public SAMLContextProviderImpl contextProvider() {
    return new SAMLContextProviderImpl();
  }

  // Initialization of OpenSAML library
  @Bean
  public static SAMLBootstrap sAMLBootstrap() {
    return new SAMLBootstrap();
  }

  // Logger for SAML messages and events
  @Bean
  public SAMLDefaultLogger samlLogger() {
    return new SAMLDefaultLogger();
  }

  // SAML 2.0 WebSSO Assertion Consumer
  @Bean
  public WebSSOProfileConsumer webSSOprofileConsumer() {
    return new WebSSOProfileConsumerImpl();
  }

  // SAML 2.0 Holder-of-Key WebSSO Assertion Consumer
  @Bean
  public WebSSOProfileConsumerHoKImpl hokWebSSOprofileConsumer() {
    return new WebSSOProfileConsumerHoKImpl();
  }

  // SAML 2.0 Web SSO profile
  @Bean
  public WebSSOProfile webSSOprofile() {
    return new WebSSOProfileImpl();
  }

  // SAML 2.0 Holder-of-Key Web SSO profile
  @Bean
  public WebSSOProfileConsumerHoKImpl hokWebSSOProfile() {
    return new WebSSOProfileConsumerHoKImpl();
  }

  // SAML 2.0 ECP profile
  @Bean
  public WebSSOProfileECPImpl ecpprofile() {
    return new WebSSOProfileECPImpl();
  }

  @Bean
  public SingleLogoutProfile logoutprofile() {
    return new SingleLogoutProfileImpl();
  }

  // Central storage of cryptographic keys
  @Bean
  public KeyManager keyManager() {
    DefaultResourceLoader loader = new DefaultResourceLoader();
    Resource storeFile = loader
        .getResource("classpath:/trust.keystore");
    String storePass = "changeit";
    Map<String, String> passwords = new HashMap<String, String>();
    passwords.put("saml", "changeit");
    String defaultKey = "saml";
    return new JKSKeyManager(storeFile, storePass, passwords, defaultKey);
  }

  // Setup TLS Socket Factory
  @Bean
  public TLSProtocolConfigurer tlsProtocolConfigurer() {
    return new TLSProtocolConfigurer();
  }

  @Bean
  public WebSSOProfileOptions defaultWebSSOProfileOptions() {
    WebSSOProfileOptions webSSOProfileOptions = new WebSSOProfileOptions();
    webSSOProfileOptions.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);
    webSSOProfileOptions.setNameID("urn:oasis:names:tc:SAML:2.0:nameid-format:transient");
    webSSOProfileOptions.setIncludeScoping(false);
    return webSSOProfileOptions;
  }

  // Entry point to initialize authentication, default values taken from
  // properties file
  @Bean
  public SAMLEntryPoint samlEntryPoint() {
    SAMLEntryPoint samlEntryPoint = new SAMLEntryPoint();
    samlEntryPoint.setDefaultProfileOptions(defaultWebSSOProfileOptions());
    return samlEntryPoint;
  }

  // Setup advanced info about metadata
  @Bean
  public ExtendedMetadata extendedMetadata() {
    ExtendedMetadata extendedMetadata = new ExtendedMetadata();
    extendedMetadata.setIdpDiscoveryEnabled(false);
    extendedMetadata.setSignMetadata(false);
    extendedMetadata.setEcpEnabled(true);
    return extendedMetadata;
  }

  // IDP Discovery Service
  @Bean
  public SAMLDiscovery samlIDPDiscovery() {
    SAMLDiscovery idpDiscovery = new SAMLDiscovery();
    idpDiscovery.setIdpSelectionPath("/discovery");
    return idpDiscovery;
  }

  @Bean
  @Qualifier("keycloak")
  public ExtendedMetadataDelegate keycloakMetadataProvider()
      throws MetadataProviderException
  {
    String keycloakMetadataURL = "http://localhost:8080/auth/realms/master/protocol/saml/descriptor";
    HTTPMetadataProvider httpMetadataProvider =
        new HTTPMetadataProvider(this.backgroundTaskTimer, httpClient(), keycloakMetadataURL);
    httpMetadataProvider.setParserPool(parserPool());
    ExtendedMetadataDelegate extendedMetadataDelegate =
        new ExtendedMetadataDelegate(httpMetadataProvider, extendedMetadata());
    extendedMetadataDelegate.setMetadataTrustCheck(true);
    extendedMetadataDelegate.setMetadataRequireSignature(false);
    backgroundTaskTimer.purge();
    return extendedMetadataDelegate;
  }

  // IDP Metadata configuration - paths to metadata of IDPs
  // is here
  // Do no forget to call iniitalize method on providers
  @Bean
  @Qualifier("metadata")
  public CachingMetadataManager metadata() throws MetadataProviderException {
    List<MetadataProvider> providers = new ArrayList<MetadataProvider>();
    providers.add(keycloakMetadataProvider());
    return new CachingMetadataManager(providers);
  }

  // Filter automatically generates default SP metadata
  @Bean
  public MetadataGenerator metadataGenerator() {
    MetadataGenerator metadataGenerator = new MetadataGenerator();
    metadataGenerator.setEntityId("ca:redtoad:sp");
    metadataGenerator.setBindingsSSO(Arrays.asList("post", "artifact", "paos"));
    metadataGenerator.setExtendedMetadata(extendedMetadata());
    metadataGenerator.setIncludeDiscoveryExtension(false);
    metadataGenerator.setKeyManager(keyManager());
    return metadataGenerator;
  }

  // The filter is waiting for connections on URL suffixed with filterSuffix
  // and presents SP metadata there
  @Bean
  public MetadataDisplayFilter metadataDisplayFilter()
      throws MetadataProviderException
  {
    MetadataDisplayFilter metadataDisplayFilter = new MetadataDisplayFilter();
    metadataDisplayFilter.setContextProvider(contextProvider());
    metadataDisplayFilter.setFilterProcessesUrl("/metadata");
    metadataDisplayFilter.setKeyManager(keyManager());
    metadataDisplayFilter.setManager(metadata());
    return metadataDisplayFilter;
  }

  // Handler deciding where to redirect user after successful login
  @Bean
  public SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler() {
    return new SavedRequestAwareAuthenticationSuccessHandler()
    {
      @Override
      public void onAuthenticationSuccess(
          HttpServletRequest request,
          HttpServletResponse response,
          Authentication authentication) throws ServletException, IOException
      {
        request.getSession().setAttribute(AUTHENTICATED_USER, authentication.getPrincipal());
        super.onAuthenticationSuccess(request, response, authentication);
      }
    };
  }

  // Handler deciding where to redirect user after failed login
  @Bean
  public SimpleUrlAuthenticationFailureHandler authenticationFailureHandler() {
    SimpleUrlAuthenticationFailureHandler failureHandler =
        new SimpleUrlAuthenticationFailureHandler();
    failureHandler.setUseForward(true);
    failureHandler.setDefaultFailureUrl("/error");
    return failureHandler;
  }

  @Bean
  public SAMLWebSSOHoKProcessingFilter samlWebSSOHoKProcessingFilter() throws Exception {
    SAMLWebSSOHoKProcessingFilter samlWebSSOHoKProcessingFilter = new SAMLWebSSOHoKProcessingFilter();
    samlWebSSOHoKProcessingFilter.setAuthenticationSuccessHandler(successRedirectHandler());
    samlWebSSOHoKProcessingFilter.setAuthenticationManager(authenticationManager());
    samlWebSSOHoKProcessingFilter.setAuthenticationFailureHandler(authenticationFailureHandler());
    return samlWebSSOHoKProcessingFilter;
  }

  // Processing filter for WebSSO profile messages
  @Bean
  public SAMLProcessingFilter samlWebSSOProcessingFilter() throws Exception {
    SAMLProcessingFilter samlWebSSOProcessingFilter = new SAMLProcessingFilter();
    samlWebSSOProcessingFilter.setFilterProcessesUrl("/callback/login");
    samlWebSSOProcessingFilter.setAuthenticationManager(authenticationManager());
    samlWebSSOProcessingFilter.setAuthenticationSuccessHandler(successRedirectHandler());
    samlWebSSOProcessingFilter.setAuthenticationFailureHandler(authenticationFailureHandler());
    return samlWebSSOProcessingFilter;
  }

  @Bean
  public MetadataGeneratorFilter metadataGeneratorFilter() {
    return new MetadataGeneratorFilter(metadataGenerator());
  }

  // Handler for successful logout
  @Bean
  public SimpleUrlLogoutSuccessHandler successLogoutHandler() {
    SimpleUrlLogoutSuccessHandler successLogoutHandler = new SimpleUrlLogoutSuccessHandler();
    successLogoutHandler.setDefaultTargetUrl("/");
    return successLogoutHandler;
  }

  // Logout handler terminating local session
  @Bean
  public SecurityContextLogoutHandler logoutHandler() {
    SecurityContextLogoutHandler logoutHandler =
        new SecurityContextLogoutHandler();
    logoutHandler.setInvalidateHttpSession(true);
    logoutHandler.setClearAuthentication(true);
    return logoutHandler;
  }

  // Filter processing incoming logout messages
  // First argument determines URL user will be redirected to after successful
  // global logout
  @Bean
  public SAMLLogoutProcessingFilter samlLogoutProcessingFilter() {
    SAMLLogoutProcessingFilter samlLogoutProcessingFilter =
        new SAMLLogoutProcessingFilter(successLogoutHandler(), logoutHandler());
    samlLogoutProcessingFilter.setFilterProcessesUrl("/callback/logout");
    return samlLogoutProcessingFilter;
  }

  // Overrides default logout processing filter with the one processing SAML
  // messages
  @Bean
  public SAMLLogoutFilter samlLogoutFilter() {
    SAMLLogoutFilter samlLogoutFilter = new SAMLLogoutFilter(successLogoutHandler(),
        new LogoutHandler[]{logoutHandler()},
        new LogoutHandler[]{logoutHandler()});
    samlLogoutFilter.setFilterProcessesUrl("/logout");
    return samlLogoutFilter;
  }

  // Bindings
  private ArtifactResolutionProfile artifactResolutionProfile() {
    final ArtifactResolutionProfileImpl artifactResolutionProfile =
        new ArtifactResolutionProfileImpl(httpClient());
    artifactResolutionProfile.setProcessor(new SAMLProcessorImpl(soapBinding()));
    return artifactResolutionProfile;
  }

  @Bean
  public HTTPArtifactBinding artifactBinding(ParserPool parserPool, VelocityEngine velocityEngine) {
    return new HTTPArtifactBinding(parserPool, velocityEngine, artifactResolutionProfile());
  }

  @Bean
  public HTTPSOAP11Binding soapBinding() {
    return new HTTPSOAP11Binding(parserPool());
  }

  @Bean
  public HTTPPostBinding httpPostBinding() {
    return new HTTPPostBinding(parserPool(), velocityEngine());
  }

  @Bean
  public HTTPRedirectDeflateBinding httpRedirectDeflateBinding() {
    return new HTTPRedirectDeflateBinding(parserPool());
  }

  @Bean
  public HTTPSOAP11Binding httpSOAP11Binding() {
    return new HTTPSOAP11Binding(parserPool());
  }

  @Bean
  public HTTPPAOS11Binding httpPAOS11Binding() {
    return new HTTPPAOS11Binding(parserPool());
  }

  // Processor
  @Bean
  public SAMLProcessorImpl processor() {
    Collection<SAMLBinding> bindings = new ArrayList<SAMLBinding>();
    bindings.add(httpRedirectDeflateBinding());
    bindings.add(httpPostBinding());
    bindings.add(artifactBinding(parserPool(), velocityEngine()));
    bindings.add(httpSOAP11Binding());
    bindings.add(httpPAOS11Binding());
    return new SAMLProcessorImpl(bindings);
  }

  /**
   * Define the security filter chain in order to support SSO Auth by using SAML 2.0
   *
   * @return Filter chain proxy
   */
  @Bean
  public FilterChainProxy samlFilter() throws Exception {
    List<SecurityFilterChain> chains = new ArrayList<SecurityFilterChain>();
    chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/login/**"),
        samlEntryPoint()));
    chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/logout/**"),
        samlLogoutFilter()));
    chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/metadata/**"),
        metadataDisplayFilter()));
    chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/callback/login/**"),
        samlWebSSOProcessingFilter()));
    chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/SSOHoK/**"),
        samlWebSSOHoKProcessingFilter()));
    chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/callback/logout/**"),
        samlLogoutProcessingFilter()));
    chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/discovery/**"),
        samlIDPDiscovery()));
    return new FilterChainProxy(chains);
  }

  /**
   * Returns the authentication manager currently used by Spring.
   * It represents a bean definition with the aim allow wiring from
   * other classes performing the Inversion of Control (IoC).
   */
  @Bean
  @Override
  public AuthenticationManager authenticationManagerBean() throws Exception {
    return super.authenticationManagerBean();
  }

  /**
   * Defines the web based security configuration.
   *
   * @param http It allows configuring web based security for specific http requests.
   */
  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.httpBasic().authenticationEntryPoint(samlEntryPoint());
    http.addFilterBefore(metadataGeneratorFilter(), ChannelProcessingFilter.class)
        .addFilterAfter(samlFilter(), BasicAuthenticationFilter.class).addFilterBefore(samlFilter(), CsrfFilter.class);
    http.authorizeRequests().antMatchers("/", "/metadata").permitAll().anyRequest().authenticated();
    http.logout().disable();        // The logout procedure is already handled by SAML filters.
  }

  /**
   * Sets a custom authentication provider.
   *
   * @param auth SecurityBuilder used to create an AuthenticationManager.
   */
  @Override
  protected void configure(AuthenticationManagerBuilder auth) {
    auth.authenticationProvider(samlAuthenticationProvider());
  }

  @Override
  public void afterPropertiesSet() {
    init();
  }

  @Override
  public void destroy() {
    shutdown();
  }

  public static Envelope detachBodyUnknownXMLObjectsIntoNewEnvelope(Envelope envelope) {
    Envelope env = new EnvelopeBuilder().buildObject();
    Body body = new BodyBuilder().buildObject();
    Header header = new HeaderBuilder().buildObject(); 
    env.setHeader(header);
    for (XMLObject xmlObject : envelope.getBody().getUnknownXMLObjects()) {
      xmlObject.detach();
      body.getUnknownXMLObjects().add(xmlObject);
    }
    env.setBody(body);
    return env;
  }

  public static String toString(InputStream inputStream) {
    return new BufferedReader(new InputStreamReader(inputStream)).lines()
        .collect(Collectors.joining(System.lineSeparator()));
  }
}
