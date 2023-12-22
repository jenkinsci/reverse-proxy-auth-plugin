package org.jenkinsci.plugins.reverse_proxy_auth.data;

import java.util.HashSet;
import java.util.Set;
import org.acegisecurity.GrantedAuthority;

/**
 * @author Wilder Rodrigues (wrodrigues@schubergphilis.com)
 */
public class GroupSearchTemplate extends SearchTemplate {

  public GroupSearchTemplate(String userOrGroup) {
    super(userOrGroup);
  }

  @Override
  public Set<String> processAuthorities(GrantedAuthority[] authorities) {
    return this.doProcess(authorities);
  }

  @Override
  protected Set<String> doProcess(GrantedAuthority[] authorities) {
    // TODO: refactoring: use singleton
    Set<String> authorityValues = new HashSet<String>();
    authorityValues.add(userOrGroup);

    return authorityValues;
  }
}
