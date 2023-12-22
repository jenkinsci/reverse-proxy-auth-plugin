package org.jenkinsci.plugins.reverse_proxy_auth.data;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.HashSet;
import java.util.Set;
import org.acegisecurity.GrantedAuthority;

/**
 * @author Wilder Rodrigues (wrodrigues@schubergphilis.com)
 */
public abstract class SearchTemplate {

  protected String userOrGroup;

  public SearchTemplate(String userOrGroup) {
    this.userOrGroup = userOrGroup;
  }

  public abstract Set<String> processAuthorities(final GrantedAuthority[] authorities);

  /**
   * Process authorities.
   *
   * @param authorities Authorities. Can be {@code null}.
   * @return Set of group and user names
   */
  @NonNull
  protected Set<String> doProcess(final @CheckForNull GrantedAuthority[] authorities) {
    // TODO: refactoring: use emptySet() ?
    Set<String> authorityValues = new HashSet<String>();
    if (authorities != null) {
      for (int i = 0; i < authorities.length; i++) {

        String authority = authorities[i].getAuthority();

        if (authority.toUpperCase().startsWith("CN=")) {
          String groupName;
          int index = authority.indexOf(',');
          if (index > 0) {
            groupName = authority.substring(3, authority.indexOf(','));
          } else {
            groupName = authority.substring(3, authority.length());
          }
          authorityValues.add(groupName);
        } else {
          authorityValues.add(authority);
        }
      }
    }
    return authorityValues;
  }
}
