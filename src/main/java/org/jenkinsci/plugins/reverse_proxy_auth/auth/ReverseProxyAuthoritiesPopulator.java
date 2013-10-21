package org.jenkinsci.plugins.reverse_proxy_auth.auth;

import org.acegisecurity.GrantedAuthority;
import org.jenkinsci.plugins.reverse_proxy_auth.ReverseProxySecurityRealm.ReverseProxyUserDetails;

public interface ReverseProxyAuthoritiesPopulator {

	GrantedAuthority[] getGrantedAuthorities(GrantedAuthority[] contextAuthorities, ReverseProxyUserDetails userDetails);
}