package org.jenkinsci.plugins.reverse_proxy_auth;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.acegisecurity.GrantedAuthority;

public class ReverseProxySearchTemplate {

	public Set<String> executeReadOnly(ContextExecutor ce) {
		return ce.executeWithContext();
	}

	public Set<String> searchForSingleAttributeValues(final String base, final GrantedAuthority [] authorities, final String attributeName) {

		class SingleAttributeSearchCallback implements ContextExecutor {

			public Set<String> executeWithContext() {

				Set<String> unionOfValues = new HashSet<String>();

				String [] groups = base.toLowerCase().split(",");
				List<String> groupsList = Arrays.asList(groups);
				
				for (int i = 0; i < authorities.length; i++) {
					
					String authority = authorities[i].getAuthority().toLowerCase();
					if (groupsList.contains(authority)) {
						unionOfValues.add(authority);
					}

				}

				return unionOfValues;
			}
		}
		return executeReadOnly(new SingleAttributeSearchCallback());
	}
}

interface ContextExecutor {
	Set<String> executeWithContext();
}