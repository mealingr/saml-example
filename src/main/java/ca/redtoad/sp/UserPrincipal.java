package ca.redtoad.sp;

import java.security.Principal;
import java.util.Collections;
import java.util.List;

import org.opensaml.saml2.core.Attribute;

public class UserPrincipal
    implements Principal
{
  private final String name;

  private final List<Attribute> attributes;

  public UserPrincipal(String name, List<Attribute> attributes) {
    this.name = name;
    this.attributes = Collections.unmodifiableList(attributes);
  }

  @Override
  public String getName() {
    return name;
  }

  public List<Attribute> getAttributes() {
    return attributes;
  }
}
