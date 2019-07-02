package ca.redtoad.sp;

public class Credential
{
  private static final org.opensaml.security.credential.Credential SERVICE_PROVIDER_CREDENTIAL =
      SAMLUtil.getServiceProviderCredential();

  private static final org.opensaml.security.credential.Credential IDENTITY_PROVIDER_CREDENTIAL =
      SAMLUtil.getIdentityProviderCredential();

  public static org.opensaml.security.credential.Credential getServiceProviderCredential() {
    return SERVICE_PROVIDER_CREDENTIAL;
  }

  public static org.opensaml.security.credential.Credential getIdentityProviderCredential() {
    return IDENTITY_PROVIDER_CREDENTIAL;
  }
}
