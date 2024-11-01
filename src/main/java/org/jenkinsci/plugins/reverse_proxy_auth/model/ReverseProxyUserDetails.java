package org.jenkinsci.plugins.reverse_proxy_auth.model;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import java.util.Collection;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttributes;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * @author Wilder Rodrigues (wrodrigues@schubergphilis.com)
 */
public class ReverseProxyUserDetails implements UserDetails {

    private static final long serialVersionUID = 8070729070782792157L;

    private static final Attributes attributes = new BasicAttributes();

    @CheckForNull
    private Collection<? extends GrantedAuthority> authorities;

    @CheckForNull
    private String username;

    @Override
    @CheckForNull
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    public void setAuthorities(@CheckForNull Collection<? extends GrantedAuthority> authorities) {
        this.authorities = authorities;
    }

    @Override
    public String getPassword() {
        return "";
    }

    @Override
    @CheckForNull
    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    public Attributes getAttributes() {
        return attributes;
    }
}
