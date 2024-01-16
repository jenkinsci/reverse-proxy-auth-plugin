package org.jenkinsci.plugins.reverse_proxy_auth.auth;

import org.acegisecurity.GrantedAuthority;
import org.jenkinsci.plugins.reverse_proxy_auth.model.ReverseProxyUserDetails;

public interface ReverseProxyAuthoritiesPopulator {

    GrantedAuthority[] getGrantedAuthorities(ReverseProxyUserDetails userDetails);
}
