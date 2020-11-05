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

package org.jenkinsci.plugins.reverse_proxy_auth.auth;

import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationServiceException;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.providers.dao.AbstractUserDetailsAuthenticationProvider;
import org.acegisecurity.userdetails.UserDetails;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jenkinsci.plugins.reverse_proxy_auth.model.ReverseProxyUserDetails;
import org.springframework.dao.DataAccessException;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;


/**
 * @author Wilder Rodrigues (wrodrigues@schubergphilis.com)
 */
public class ReverseProxyAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {
	private static final Log logger = LogFactory.getLog(ReverseProxyAuthenticationProvider.class);

	private ReverseProxyAuthenticator authenticator;
	private ReverseProxyAuthoritiesPopulator authoritiesPopulator;
	private boolean includeDetailsObject = true;

	/**
	 * Create an instance with the supplied authenticator and authorities populator implementations.
	 *
	 * @param authenticator the authentication strategy (bind, password comparison, etc)
	 *          to be used by this provider for authenticating users.
	 * @param authoritiesPopulator the strategy for obtaining the authorities for a given user after they've been
	 *          authenticated.
	 */
	public ReverseProxyAuthenticationProvider(ReverseProxyAuthenticator authenticator, ReverseProxyAuthoritiesPopulator authoritiesPopulator) {
		setAuthenticator(authenticator);
		setAuthoritiesPopulator(authoritiesPopulator);
	}

	/**
	 * Creates an instance with the supplied authenticator and a null authorities populator.
	 * In this case, the authorities must be mapped from the user context.
	 *
	 * @param authenticator the authenticator strategy.
	 */
	public ReverseProxyAuthenticationProvider(ReverseProxyAuthenticator authenticator) {
		setAuthenticator(authenticator);
		setAuthoritiesPopulator(new NullAuthoritiesPopulator());
	}

	private void setAuthenticator(ReverseProxyAuthenticator authenticator) {
		Assert.notNull(authenticator, "An Authenticator must be supplied");
		this.authenticator = authenticator;
	}

	private ReverseProxyAuthenticator getAuthenticator() {
		return authenticator;
	}

	private void setAuthoritiesPopulator(ReverseProxyAuthoritiesPopulator authoritiesPopulator) {
		Assert.notNull(authoritiesPopulator, "An AuthoritiesPopulator must be supplied");
		this.authoritiesPopulator = authoritiesPopulator;
	}

	protected ReverseProxyAuthoritiesPopulator getAuthoritiesPopulator() {
		return authoritiesPopulator;
	}

	@Override
	protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication)
			throws AuthenticationException {
		//Do not do anything here!

		// if (!userDetails.getPassword().equals(authentication.getCredentials().toString())) {
		//     throw new BadCredentialsException(messages.getMessage(
		//             "AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"),
		//             includeDetailsObject ? userDetails : null);
		// }
	}

	/**
	 * Creates the final <tt>UserDetails</tt> object that will be returned by the provider once the user has
	 * been authenticated.<p>The <tt>ReverseProxyAuthoritiesPopulator</tt> will be used to create the granted
	 * authorites for the user.</p>
	 *  <p>Can be overridden to customize the creation of the final UserDetails instance. The default will
	 * merge any additional authorities retrieved from the populator with the propertis of original <tt>ldapUser</tt>
	 * object and set the values of the username and password.</p>
	 *
	 * @param user The intermediate LdapUserDetails instance returned by the authenticator.
	 * @param username the username submitted to the provider
	 * @param password the password submitted to the provider
	 *
	 * @return The UserDetails for the successfully authenticated user.
	 */
	protected UserDetails createUserDetails(ReverseProxyUserDetails user, String username, String password) {
		user.setUsername(username);

		// Hack for now to pass user's own authorities. Will make the full greanted authorities as a bean in the future.
		GrantedAuthority[] extraAuthorities = getAuthoritiesPopulator().getGrantedAuthorities(user);
		user.setAuthorities(extraAuthorities);

		return user;
	}

	@Override
	protected UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication)
			throws AuthenticationException {
		if (!StringUtils.hasLength(username)) {
			throw new BadCredentialsException("Empty Username");
		}

		if (logger.isDebugEnabled()) {
			logger.debug("Retrieving user " + username);
		}

		String password = (String) authentication.getCredentials();

		// We do not need this when doing Reverse Proxy Auth
		//Assert.notNull(password, "Null password was supplied in authentication token");

		// if (password.length() == 0) {
		//    logger.debug("Rejecting empty password for user " + username);
		//    throw new BadCredentialsException(messages.getMessage("LdapAuthenticationProvider.emptyPassword",
		//            "Empty Password"));
		//}

		try {
			ReverseProxyUserDetails revProxyU = getAuthenticator().authenticate(username, password);

			return createUserDetails(revProxyU, username, password);

		} catch (DataAccessException ldapAccessFailure) {
			throw new AuthenticationServiceException(ldapAccessFailure.getMessage(), ldapAccessFailure);
		}
	}

	public boolean isIncludeDetailsObject() {
		return includeDetailsObject;
	}

	public void setIncludeDetailsObject(boolean includeDetailsObject) {
		this.includeDetailsObject = includeDetailsObject;
	}

	private static class NullAuthoritiesPopulator implements ReverseProxyAuthoritiesPopulator {
		public GrantedAuthority[] getGrantedAuthorities(ReverseProxyUserDetails userDetails) {
			return new GrantedAuthority[0];
		}
	}
}
