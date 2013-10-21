package org.jenkinsci.plugins.reverse_proxy_auth;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.acegisecurity.GrantedAuthority;

/**
 * @author Wilder Rodrigues (wrodrigues@schubergphilis.com)
 */
public class ReverseProxySearchTemplate {

	public Set<String> executeReadOnly(ContextExecutor ce) {
		return ce.executeWithContext();
	}

	public Set<String> searchForSingleAttributeValues(final String base, final GrantedAuthority [] authorities, final String attributeName) {

		class SingleAttributeSearchCallback implements ContextExecutor {

			public Set<String> executeWithContext() {

				Set<String> intersectionValues = new HashSet<String>();
				Set<String> authorityValues = new HashSet<String>();

				List<String> groupsList = splitGroups(base);
				intersectionValues.addAll(groupsList);
				
				for (int i = 0; i < authorities.length; i++) {
					
					String authority = authorities[i].getAuthority().toLowerCase();
					List<String> authorityList = splitGroups(authority);
					
					authorityValues.addAll(authorityList);
				}

				intersectionValues.retainAll(authorityValues);
				
				return intersectionValues;
			}
		}
		return executeReadOnly(new SingleAttributeSearchCallback());
	}
	
	private List<String> splitGroups(String base) {
		String [] groups = base.toLowerCase().split(",");
		List<String> groupsList = Arrays.asList(groups);
		
		return groupsList;
	}
}

interface ContextExecutor {
	Set<String> executeWithContext();
}
