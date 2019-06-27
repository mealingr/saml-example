package ca.redtoad;

import org.opensaml.saml.common.xml.SAMLConstants;
import org.pac4j.core.http.callback.NoParameterCallbackUrlResolver;
import org.pac4j.saml.client.SAML2Client;
import org.pac4j.saml.config.SAML2Configuration;

public class SAML2ClientBuilder
{
  private static SAML2Client saml2Client = null;

  public SAML2Client build() {
    if (saml2Client == null) {
      SAML2Configuration config = new SAML2Configuration();
      config.setServiceProviderEntityId("sp_entity_id");
      config.setIdentityProviderMetadataResourceUrl(getClass().getResource("/docker-test-saml-idp.xml").toString());
      config.setSpLogoutRequestBindingType(SAMLConstants.SAML2_REDIRECT_BINDING_URI);

      // keytool -genkey -keyalg RSA -alias saml -keypass changeit -keystore trust.keystore -storepass changeit
      config.setKeystorePath("trust.keystore");
      config.setKeystorePassword("changeit");
      config.setPrivateKeyPassword("changeit");
      config.setKeystoreAlias("saml");
      config.setAuthnRequestBindingType("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");

      saml2Client = new SAML2Client(config);
      saml2Client.setCallbackUrl("http://localhost:8081/callback");
      // in pac4j all auth methods (e.g. saml2, facebook, etc) expect to use same callback endpoint
      // and so pac4j uses client_name query param to distinguish, but these can be a pain for the identity provider
      saml2Client.setCallbackUrlResolver(new NoParameterCallbackUrlResolver());
      saml2Client.init();
    }
    return saml2Client;
  }
}
