package org.jenkinsci.plugins.reverse_proxy_auth.data;

import java.util.HashSet;
import java.util.Set;

import org.acegisecurity.GrantedAuthority;

/**
 * @author Wilder Rodrigues (wrodrigues@schubergphilis.com)
 */
public class UserSearchTemplate extends SearchTemplate {

	public UserSearchTemplate(String userOrGroup) {
		super(userOrGroup);
	}

	@Override
	public Set<String> processAuthorities(GrantedAuthority[] authorities) {
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