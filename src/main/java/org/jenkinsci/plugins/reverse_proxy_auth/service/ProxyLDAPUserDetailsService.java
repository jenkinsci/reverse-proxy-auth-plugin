package org.jenkinsci.plugins.reverse_proxy_auth.service;

import hudson.security.UserMayOrMayNotExistException;

import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttributes;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.ldap.LdapDataAccessException;
import org.acegisecurity.ldap.LdapUserSearch;
import org.acegisecurity.providers.ldap.LdapAuthoritiesPopulator;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.acegisecurity.userdetails.ldap.LdapUserDetails;
import org.acegisecurity.userdetails.ldap.LdapUserDetailsImpl;
import org.apache.commons.collections.map.LRUMap;
import org.jenkinsci.plugins.reverse_proxy_auth.ReverseProxySecurityRealm;
import org.springframework.dao.DataAccessException;
import org.springframework.web.context.WebApplicationContext;

public class ProxyLDAPUserDetailsService implements UserDetailsService {

	private static final Logger LOGGER = Logger.getLogger(ProxyLDAPUserDetailsService.class.getName());
	private static final int RETRY_TIMES = 3;
	private static final long MAX_WAIT_INTERVAL = 5000L; // 5 seconds

	public final LdapUserSearch ldapSearch;
	public final LdapAuthoritiesPopulator authoritiesPopulator;

	/**
	 * {@link BasicAttributes} in LDAP tend to be bulky (about 20K at size), so interning them
	 * to keep the size under control. When a programmatic client is not smart enough to
	 * reuse a session, this helps keeping the memory consumption low.
	 */
	private final LRUMap attributesCache = new LRUMap(32);

	public ProxyLDAPUserDetailsService(ReverseProxySecurityRealm securityRealm, WebApplicationContext appContext) {
		ldapSearch = securityRealm.extractBean(LdapUserSearch.class, appContext);
		authoritiesPopulator = securityRealm.extractBean(LdapAuthoritiesPopulator.class, appContext);
	}

	public ProxyLDAPUserDetailsService(LdapUserSearch ldapSearch, LdapAuthoritiesPopulator authoritiesPopulator) {
		this.ldapSearch = ldapSearch;
		this.authoritiesPopulator = authoritiesPopulator;
	}

	public LdapUserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
		int retries = 0;
		while (retries < RETRY_TIMES) {
			try {
				LdapUserDetails ldapUser = ldapSearch.searchForUser(username);
				// LdapUserSearch does not populate granted authorities (group search).
				// Add those, as done in LdapAuthenticationProvider.createUserDetails().
				if (ldapUser != null) {
					LdapUserDetailsImpl.Essence user = new LdapUserDetailsImpl.Essence(ldapUser);

					// intern attributes
					Attributes v = ldapUser.getAttributes();
					if (v instanceof BasicAttributes) { // BasicAttributes.equals is what makes the interning possible
						synchronized (attributesCache) {
							Attributes vv = (Attributes)attributesCache.get(v);
							if (vv==null)   attributesCache.put(v,vv=v);
							user.setAttributes(vv);
						}
					}

					GrantedAuthority[] extraAuthorities = authoritiesPopulator.getGrantedAuthorities(ldapUser);
					for (GrantedAuthority extraAuthority : extraAuthorities) {
						user.addAuthority(extraAuthority);
					}
					ldapUser = user.createUserDetails();
				}

				return ldapUser;
			} catch (LdapDataAccessException ldapEx) {
				long waitTime = Math.min(getWaitTimeExp(retries), MAX_WAIT_INTERVAL);
				String msg = String.format(
						"Failed to search LDAP for username %s, will retry after waiting for %d milliseconds",
						username, waitTime);
				LOGGER.log(Level.WARNING, msg, ldapEx);
				try {
					Thread.sleep(waitTime);
				} catch (InterruptedException intEx) {
					LOGGER.log(Level.WARNING, "Thread was interrupted while sleeping!");
				}
				retries++;
			}
		}
		throw new UserMayOrMayNotExistException("Failed to search LDAP for user after all the retries.");
	}

	/*
	 * Returns the next wait interval, in milliseconds, using an exponential
	 * backoff algorithm.
	 */
	private long getWaitTimeExp(int retryCount) {

		long waitTime = ((long) Math.pow(2, retryCount) * 1000L);

		return waitTime;
	}
}