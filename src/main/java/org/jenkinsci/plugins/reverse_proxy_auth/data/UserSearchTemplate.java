package org.jenkinsci.plugins.reverse_proxy_auth.data;

import java.util.Set;
import org.acegisecurity.GrantedAuthority;

/**
 * @author Wilder Rodrigues (wrodrigues@schubergphilis.com)
 */
public class UserSearchTemplate extends SearchTemplate {

  public UserSearchTemplate(String userOrGroup) {
    super(userOrGroup);
  }

  @Override
  public Set<String> processAuthorities(GrantedAuthority[] authorities) {
    return doProcess(authorities);
  }
}
