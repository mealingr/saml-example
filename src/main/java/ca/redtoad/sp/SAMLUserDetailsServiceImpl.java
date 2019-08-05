package ca.redtoad.sp;

import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.stereotype.Service;

@Service
public class SAMLUserDetailsServiceImpl
    implements SAMLUserDetailsService
{
  public Object loadUserBySAML(SAMLCredential credential) {
    return new UserPrincipal(credential.getNameID().getValue(), credential.getAttributes());
  }
}
