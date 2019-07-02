package ca.redtoad.sp;

import java.security.Principal;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class UserPrincipal
    implements Principal
{
  private final String name;

  private final Map<String, List<String>> attributes;

  public UserPrincipal(String name, Map<String, List<String>> attributes) {
    this.name = name;
    this.attributes = Collections.unmodifiableMap(attributes);
  }

  @Override
  public String getName() {
    return name;
  }

  public Map<String, List<String>> getAttributes() {
    return attributes;
  }
}
