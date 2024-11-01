package org.jenkinsci.plugins.reverse_proxy_auth.auth;

import java.util.Collection;
import org.jenkinsci.plugins.reverse_proxy_auth.model.ReverseProxyUserDetails;
import org.springframework.security.core.GrantedAuthority;

public interface ReverseProxyAuthoritiesPopulator {

    Collection<? extends GrantedAuthority> getGrantedAuthorities(ReverseProxyUserDetails userDetails);
}
