package org.jenkinsci.plugins.reverse_proxy_auth.model;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.util.Arrays;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttributes;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.UserDetails;

/**
 * @author Wilder Rodrigues (wrodrigues@schubergphilis.com)
 */
public class ReverseProxyUserDetails implements UserDetails {

  private static final long serialVersionUID = 8070729070782792157L;

  private static final Attributes attributes = new BasicAttributes();

  @CheckForNull private GrantedAuthority[] authorities;
  @CheckForNull private String username;

  @CheckForNull
  @SuppressFBWarnings(
      value = "EI_EXPOSE_REP",
      justification = "We keep it as is due to performance reasons")
  public GrantedAuthority[] getAuthorities() {
    return authorities;
  }

  public void setAuthorities(@CheckForNull GrantedAuthority[] authorities) {
    this.authorities = authorities != null ? Arrays.copyOf(authorities, authorities.length) : null;
  }

  public String getPassword() {
    return "";
  }

  @CheckForNull
  public String getUsername() {
    return username;
  }

  public void setUsername(String username) {
    this.username = username;
  }

  public boolean isAccountNonExpired() {
    return true;
  }

  public boolean isAccountNonLocked() {
    return true;
  }

  public boolean isCredentialsNonExpired() {
    return true;
  }

  public boolean isEnabled() {
    return true;
  }

  public Attributes getAttributes() {
    return attributes;
  }
}
