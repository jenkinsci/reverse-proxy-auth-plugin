package org.jenkinsci.plugins.reverse_proxy_auth.service;

import static hudson.Util.fixNull;
import hudson.security.SecurityRealm;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.ldap.InitialDirContextFactory;
import org.acegisecurity.providers.ldap.LdapAuthoritiesPopulator;
import org.acegisecurity.providers.ldap.populator.DefaultLdapAuthoritiesPopulator;
import org.acegisecurity.userdetails.ldap.LdapUserDetails;

/**
 * {@link LdapAuthoritiesPopulator} that adds the automatic 'authenticated' role.
 */
public class ProxyLDAPAuthoritiesPopulator extends DefaultLdapAuthoritiesPopulator {

	// Make these available (private in parent class and no get methods!)
	private String rolePrefix = "ROLE_";
	private boolean convertToUpperCase = true;

	public ProxyLDAPAuthoritiesPopulator(InitialDirContextFactory initialDirContextFactory, String groupSearchBase) {
		super(initialDirContextFactory, fixNull(groupSearchBase));

		super.setRolePrefix("");
		super.setConvertToUpperCase(false);
	}

	@Override
	@SuppressWarnings("rawtypes")
	protected Set getAdditionalRoles(LdapUserDetails ldapUser) {
		return Collections.singleton(SecurityRealm.AUTHENTICATED_AUTHORITY);
	}

	@Override
	public void setRolePrefix(String rolePrefix) {
		this.rolePrefix = rolePrefix;
	}

	@Override
	public void setConvertToUpperCase(boolean convertToUpperCase) {
		this.convertToUpperCase = convertToUpperCase;
	}

	/**
	 * Retrieves the group membership in two ways.
	 *
	 * We'd like to retain the original name, but we historically used to do "ROLE_GROUPNAME".
	 * So to remain backward compatible, we make the super class pass the unmodified "groupName",
	 * then do the backward compatible translation here, so that the user gets both "ROLE_GROUPNAME" and "groupName".
	 */
	@Override
	@SuppressWarnings("unchecked")
	public Set<GrantedAuthority> getGroupMembershipRoles(String userDn, String username) {
		Set<GrantedAuthority> names = super.getGroupMembershipRoles(userDn, username);

		Set<GrantedAuthority> r = new HashSet<GrantedAuthority>(names.size()*2);
		r.addAll(names);

		for (GrantedAuthority ga : names) {
			String role = ga.getAuthority();

			// backward compatible name mangling
			if (convertToUpperCase)
				role = role.toUpperCase();
			r.add(new GrantedAuthorityImpl(rolePrefix + role));
		}

		return r;
	}
}