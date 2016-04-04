package org.jenkinsci.plugins.reverse_proxy_auth.auth;

/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import hudson.security.SecurityRealm;

import java.util.Collections;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Set;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.jenkinsci.plugins.reverse_proxy_auth.model.ReverseProxyUserDetails;


/**
 * @author Wilder rodrigues (wrodrigues@schuberphilis.com)
 */
public final class ReverseProxyAuthoritiesPopulatorImpl extends DefaultReverseProxyAuthoritiesPopulator {

	String rolePrefix = "ROLE_";
	boolean convertToUpperCase = true;

	public ReverseProxyAuthoritiesPopulatorImpl(
			Hashtable<String, GrantedAuthority[]> authContext) {
		super(authContext);

		super.setRolePrefix("");
		super.setConvertToUpperCase(false);
	}

	@Override
	protected Set<GrantedAuthority> getAdditionalRoles(ReverseProxyUserDetails proxyUser) {
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
	 * We'd like to retain the original name, but we historically used to do
	 * "ROLE_GROUPNAME". So to remain backward compatible, we make the super
	 * class pass the unmodified "groupName", then do the backward
	 * compatible translation here, so that the user gets both
	 * "ROLE_GROUPNAME" and "groupName".
	 */
	@Override
	public Set<GrantedAuthority> getGroupMembershipRoles(String username) {

		Set<GrantedAuthority> names = super.getGroupMembershipRoles(username);

		Set<GrantedAuthority> groupRoles = new HashSet<GrantedAuthority>(names.size() * 2);
		groupRoles.addAll(names);

		for (GrantedAuthority ga : names) {
			String role = ga.getAuthority();

			// backward compatible name mangling
			if (convertToUpperCase) {
				role = role.toUpperCase();
			}
			groupRoles.add(new GrantedAuthorityImpl(rolePrefix + role));
		}

		return groupRoles;
	}
}