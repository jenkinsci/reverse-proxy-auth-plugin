package org.jenkinsci.plugins.reverse_proxy_auth;

import java.util.HashSet;
import java.util.Set;

import org.acegisecurity.GrantedAuthority;

/**
 * @author Wilder Rodrigues (wrodrigues@schubergphilis.com)
 */
public class ReverseProxySearchTemplate {

	public Set<String> executeReadOnly(ContextExecutor ce) {
		return ce.executeWithContext();
	}

	public Set<String> searchForSingleAttributeValues(final GrantedAuthority [] authorities) {

		class SingleAttributeSearchCallback implements ContextExecutor {

			public Set<String> executeWithContext() {

				Set<String> authorityValues = new HashSet<String>();

				for (int i = 0; i < authorities.length; i++) {
					
					String authority = authorities[i].getAuthority();
					
					if (authority.toUpperCase().startsWith("CN=")) {
						String groupName = authority.substring(3, authority.indexOf(','));
						authorityValues.add(groupName);
					}
				}

				return authorityValues;
			}
		}
		return executeReadOnly(new SingleAttributeSearchCallback());
	}
}

interface ContextExecutor {
	Set<String> executeWithContext();
}