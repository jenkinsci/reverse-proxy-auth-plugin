package org.jenkinsci.plugins.reverse_proxy_auth.data;

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
	
	public abstract Set<String> processAuthorities(final GrantedAuthority [] authorities);
	
}