/*
 * The MIT License
 *
 * Copyright (c) 2011, CloudBees, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jenkinsci.plugins.reverse_proxy_auth;

import static hudson.Util.fixEmpty;
import static hudson.Util.fixEmptyAndTrim;
import static hudson.Util.fixNull;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import groovy.lang.Binding;
import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.security.*;
import hudson.tasks.Mailer;
import hudson.tasks.Mailer.UserProperty;
import hudson.util.Scrambler;
import hudson.util.spring.BeanBuilder;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectStreamException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.annotation.CheckForNull;
import javax.annotation.Nullable;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import jenkins.model.Jenkins;
import jenkins.security.ApiTokenProperty;

import org.acegisecurity.Authentication;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.ldap.LdapDataAccessException;
import org.acegisecurity.ldap.LdapTemplate;
import org.acegisecurity.ldap.search.FilterBasedLdapUserSearch;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.acegisecurity.userdetails.ldap.LdapUserDetails;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.plugins.reverse_proxy_auth.auth.ReverseProxyAuthoritiesPopulator;
import org.jenkinsci.plugins.reverse_proxy_auth.types.AuthorizationTypeMappingFactory;
import org.jenkinsci.plugins.reverse_proxy_auth.model.ReverseProxyUserDetails;
import org.jenkinsci.plugins.reverse_proxy_auth.types.GroupsAuthorizationType;
import org.jenkinsci.plugins.reverse_proxy_auth.types.LdapAuthorizationType;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.StaplerRequest;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.web.context.WebApplicationContext;

/**
 * @author Kohsuke Kawaguchi
 */
public class ReverseProxySecurityRealm extends SecurityRealm {

	private static final Logger LOGGER = Logger.getLogger(ReverseProxySecurityRealm.class.getName());

	/**
	 * LDAP filter to look for groups by their names.
	 *
	 * "{0}" is the group name as given by the user.
	 * See http://msdn.microsoft.com/en-us/library/aa746475(VS.85).aspx for the syntax by example.
	 * WANTED: The specification of the syntax.
	 */
	@Deprecated
	@SuppressFBWarnings(value = "MS_SHOULD_BE_FINAL", justification = "May be used in system groovy scripts")
	public static String GROUP_SEARCH = System.getProperty(LDAPSecurityRealm.class.getName()+".groupSearch",
			"(& (cn={0}) (| (objectclass=groupOfNames) (objectclass=groupOfUniqueNames) (objectclass=posixGroup)))");

	/**
	 * Interval to check user authorities via LDAP.
	 */
	private static final int CHECK_INTERVAL = 15;
	
	/**
	 * Scrambled password, used to first bind to LDAP.
	 */
	@Deprecated
	private transient final String managerPassword;

	/**
	 * Search Template used when the groups are in the header.
	 */
	@Deprecated
	private ReverseProxySearchTemplate proxyTemplate;

	/**
	 * Created in {@link #createSecurityComponents()}. Can be used to connect to LDAP.
	 */
	@Deprecated
	private transient LdapTemplate ldapTemplate;

	/**
	 * Keeps the state of connected users and their granted authorities.
	 */
	@Deprecated
	private transient Hashtable<String, GrantedAuthority[]> authContext;
	
	/**
	 * Keeps the frequency which the authorities cache is updated per connected user.
	 * The types String and Long are used for username and last time checked (in minutes) respectively.
	 */
	private transient Hashtable<String, Long> authorityUpdateCache;

	/**
	 * LDAP server name(s) separated by spaces, optionally with TCP port number, like "ldap.acme.org"
	 * or "ldap.acme.org:389" and/or with protcol, like "ldap://ldap.acme.org".
	 */
	@Deprecated
	public transient final String server;

	/**
	 * The root DN to connect to. Normally something like "dc=sun,dc=com"
	 *
	 * How do I infer this?
	 */

	@Deprecated
	public transient final String rootDN;

	/**
	 * Allow the rootDN to be inferred? Default is false.
	 * If true, allow rootDN to be blank.
	 */
	@Deprecated
	public transient final boolean inhibitInferRootDN;

	/**
	 * Specifies the relative DN from {@link #rootDN the root DN}.
	 * This is used to narrow down the search space when doing user search.
	 *
	 * Something like "ou=people" but can be empty.
	 */
	@Deprecated
	public transient final String userSearchBase;

	/**
	 * Query to locate an entry that identifies the user, given the user name string.
	 *
	 * Normally "uid={0}"
	 *
	 * @see FilterBasedLdapUserSearch
	 */
	@Deprecated
	public transient final String userSearch;

	/**
	 * This defines the organizational unit that contains groups.
	 *
	 * Normally "" to indicate the full LDAP search, but can be often narrowed down to
	 * something like "ou=groups"
	 *
	 * @see FilterBasedLdapUserSearch
	 */
	@Deprecated
	public transient final String groupSearchBase;

	/**
	 * Query to locate an entry that identifies the group, given the group name string. If non-null it will override
	 * the default specified by {@link #GROUP_SEARCH}
	 *
	 * @since 1.5
	 */
	@Deprecated
	public transient final String groupSearchFilter;

    /**
      * Query to locate the group entries that a user belongs to, given the user object. <code>{0}</code>
      * is the user's full DN while {1} is the username.
      */
    @Deprecated
	public transient final String groupMembershipFilter;

     /**
      * Attribute that should be used instead of CN as name to match a users group name to the groupSearchFilter name.
      * When {@link #groupSearchFilter} is set to search for a field other than CN e.g. <code>GroupDisplayName={0}</code> 
      * here you can configure that this (<code>GroupDisplayName</code>) or another field should be used when looking for a users groups.
      */
     @Deprecated
	 public transient String groupNameAttribute;

	/**
	 * If non-null, we use this and {@link #managerPassword}
	 * when binding to LDAP.
	 *
	 * This is necessary when LDAP doesn't support anonymous access.
	 */
	@Deprecated
	public transient final String managerDN;

	/**
	 * Sets an interval for updating the LDAP authorities. The interval is specified in minutes.
	 */
	@Deprecated
	public transient final int updateInterval;
	
	/**
	 * The authorities that are granted to the authenticated user.
	 * It is not necessary, that the authorities will be stored in the config.xml, they blow up the config.xml
	 */
	public transient GrantedAuthority[] authorities  = new GrantedAuthority[0];

	/**
	 * The name of the header which the username has to be extracted from.
	 */
	@CheckForNull
	public final String forwardedUser;
	
	/**
	 * The username retrieved from the header field, which is represented by the forwardedUser attribute.
	 */
	public String retrievedUser;

	/**
	 * Header name of the groups field.
	 */
	@Deprecated
	public transient final String headerGroups;

	/**
	 * Header name of the groups delimiter field.
	 */
	@Deprecated
	public transient final String headerGroupsDelimiter;

	@Deprecated
	public transient final boolean disableLdapEmailResolver;

    @Deprecated
	private transient  final String displayNameLdapAttribute;

    @Deprecated
    private transient final String emailAddressLdapAttribute;

	/**
	 * Custom post logout url
	 */
	public final String customLogInUrl;
	public final String customLogOutUrl;

	/**
	 * Represents the Authorization Types Mapping Factory
	 */
	private AuthorizationTypeMappingFactory authorizationTypeMappingFactory;

	@Deprecated
	public ReverseProxySecurityRealm(String forwardedUser, String headerGroups, String headerGroupsDelimiter, String customLogInUrl, String customLogOutUrl, String server, String rootDN, boolean inhibitInferRootDN,
			String userSearchBase, String userSearch, String groupSearchBase, String groupSearchFilter, String groupMembershipFilter, String groupNameAttribute, String managerDN, String managerPassword, 
			Integer updateInterval, boolean disableLdapEmailResolver, String displayNameLdapAttribute, String emailAddressLdapAttribute) {

		this.forwardedUser = fixEmptyAndTrim(forwardedUser);

		this.headerGroups = headerGroups;
		if (!StringUtils.isBlank(headerGroupsDelimiter)) {
			this.headerGroupsDelimiter = headerGroupsDelimiter.trim();
		} else {
			this.headerGroupsDelimiter = "|";
		}

		if(!StringUtils.isBlank(customLogInUrl)) {
			this.customLogInUrl = customLogInUrl;
		} else {
			this.customLogInUrl = null;
		}

		if(!StringUtils.isBlank(customLogOutUrl)) {
			this.customLogOutUrl = customLogOutUrl;
		} else {
			this.customLogOutUrl = null;
		}

		this.server = fixEmptyAndTrim(server);
		this.managerDN = fixEmpty(managerDN);
		this.managerPassword = Scrambler.scramble(fixEmpty(managerPassword));
		this.inhibitInferRootDN = inhibitInferRootDN;

		if (this.server != null) {
			if(!inhibitInferRootDN && fixEmptyAndTrim(rootDN) == null) rootDN = fixNull(inferRootDN(server));
			this.rootDN = rootDN.trim();
		} else {
			this.rootDN = null;
		}

		this.userSearchBase = fixNull(userSearchBase).trim();
		userSearch = fixEmptyAndTrim(userSearch);
		this.userSearch = userSearch != null ? userSearch : "uid={0}";
		this.groupSearchBase = fixEmptyAndTrim(groupSearchBase);
		this.groupSearchFilter = fixEmptyAndTrim(groupSearchFilter);
		this.groupMembershipFilter = fixEmptyAndTrim(groupMembershipFilter);
		this.groupNameAttribute = fixEmptyAndTrim(groupNameAttribute);

		this.updateInterval = (updateInterval == null || updateInterval <= 0) ? CHECK_INTERVAL : updateInterval;
		
		authorities = new GrantedAuthority[0];

		this.disableLdapEmailResolver = disableLdapEmailResolver;
		this.displayNameLdapAttribute = displayNameLdapAttribute;
		this.emailAddressLdapAttribute = emailAddressLdapAttribute;
	}

	@DataBoundConstructor
	public ReverseProxySecurityRealm(String forwardedUser, String headerGroups, String headerGroupsDelimiter, String customLogInUrl, String customLogOutUrl, String server, String rootDN, boolean inhibitInferRootDN,
									 String userSearchBase, String userSearch, String groupSearchBase, String groupSearchFilter, String groupMembershipFilter, String groupNameAttribute, String managerDN, String managerPassword,
									 Integer updateInterval, boolean disableLdapEmailResolver, String displayNameLdapAttribute, String emailAddressLdapAttribute, AuthorizationTypeMappingFactory authorizationTypeMappingFactory) {

		this.forwardedUser = fixEmptyAndTrim(forwardedUser);

		this.headerGroups = headerGroups;
		if (!StringUtils.isBlank(headerGroupsDelimiter)) {
			this.headerGroupsDelimiter = headerGroupsDelimiter.trim();
		} else {
			this.headerGroupsDelimiter = "|";
		}

		if(!StringUtils.isBlank(customLogInUrl)) {
			this.customLogInUrl = customLogInUrl;
		} else {
			this.customLogInUrl = null;
		}

		if(!StringUtils.isBlank(customLogOutUrl)) {
			this.customLogOutUrl = customLogOutUrl;
		} else {
			this.customLogOutUrl = null;
		}

		this.server = fixEmptyAndTrim(server);
		this.managerDN = fixEmpty(managerDN);
		this.managerPassword = Scrambler.scramble(fixEmpty(managerPassword));
		this.inhibitInferRootDN = inhibitInferRootDN;

		if (this.server != null) {
			if(!inhibitInferRootDN && fixEmptyAndTrim(rootDN) == null) rootDN = fixNull(inferRootDN(server));
			this.rootDN = rootDN.trim();
		} else {
			this.rootDN = null;
		}

		this.userSearchBase = fixNull(userSearchBase).trim();
		userSearch = fixEmptyAndTrim(userSearch);
		this.userSearch = userSearch != null ? userSearch : "uid={0}";
		this.groupSearchBase = fixEmptyAndTrim(groupSearchBase);
		this.groupSearchFilter = fixEmptyAndTrim(groupSearchFilter);
		this.groupMembershipFilter = fixEmptyAndTrim(groupMembershipFilter);
		this.groupNameAttribute = fixEmptyAndTrim(groupNameAttribute);

		this.updateInterval = (updateInterval == null || updateInterval <= 0) ? CHECK_INTERVAL : updateInterval;

		authorities = new GrantedAuthority[0];

		this.disableLdapEmailResolver = disableLdapEmailResolver;
		this.displayNameLdapAttribute = displayNameLdapAttribute;
		this.emailAddressLdapAttribute = emailAddressLdapAttribute;

		this.authorizationTypeMappingFactory = authorizationTypeMappingFactory;
	}

	public Object readResolve() throws ObjectStreamException {
		// We are using LDAP authorization model
		if (getServerUrl() != null) {
			LdapAuthorizationType ldapAuthorizationType = new LdapAuthorizationType(
					server,
					rootDN,
					inhibitInferRootDN,
					userSearchBase,
					userSearch,
					groupSearchBase,
					groupSearchFilter,
					groupMembershipFilter,
					groupNameAttribute,
					managerDN,
					managerPassword,
					displayNameLdapAttribute,
					emailAddressLdapAttribute,
					disableLdapEmailResolver,
					updateInterval
			);

			this.authorizationTypeMappingFactory = ldapAuthorizationType;
		} else {
			GroupsAuthorizationType groupsAuthorizationType = new GroupsAuthorizationType(
					headerGroups,
					headerGroupsDelimiter
			);
			this.authorizationTypeMappingFactory = groupsAuthorizationType;

		}
		return this;
	}

	/**
	 * Name of the HTTP header to look at.
	 */
	public String getForwardedUser() {
		return forwardedUser;
	}

	@Deprecated
	public String getHeaderGroups() {
		return headerGroups;
	}

	@Deprecated
	public String getHeaderGroupsDelimiter() {
		return headerGroupsDelimiter;
	}

	@Deprecated
	@CheckForNull
	public String getServerUrl() {
		if (server == null) {
			return null;
		}
		StringBuilder buf = new StringBuilder();
		boolean first = true;

		for (String s: server.split("\\s+")) {
			if (s.trim().length() == 0) continue;
			if (first) first = false; else buf.append(' ');
			buf.append(addPrefix(s));
		}
		return buf.toString();
	}

	@Deprecated
	public String getGroupSearchFilter() {
		return groupSearchFilter;
	}

	@Deprecated
	public String getGroupMembershipFilter() {
		return groupMembershipFilter;
	}

	@Deprecated
	public String getGroupNameAttribute() {
		return groupNameAttribute;
	}

	@Deprecated
	public void setGroupNameAttribute(String groupNameAttribute) {
		this.groupNameAttribute = groupNameAttribute;
	}

	@Deprecated
	public String getDisplayNameLdapAttribute() {
		return displayNameLdapAttribute;
	}

	@Deprecated
	public String getEmailAddressLdapAttribute() {
		return emailAddressLdapAttribute;
	}

	@Restricted(NoExternalUse.class)
	public AuthorizationTypeMappingFactory getAuthorizationTypeMappingFactory() {
		return authorizationTypeMappingFactory;
	}

	/**
	 * Infer the root DN.
	 *
	 * @return null if not found.
	 */
	@Deprecated
	private String inferRootDN(String server) {
		try {
			Hashtable<String,String> props = new Hashtable<String,String>();
			if(managerDN != null) {
				props.put(Context.SECURITY_PRINCIPAL, managerDN);
				props.put(Context.SECURITY_CREDENTIALS, getManagerPassword());
			}
			props.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
			//TODO: should it pass null instead and check the result?
			props.put(Context.PROVIDER_URL, toProviderUrl(fixNull(getServerUrl()), ""));

			DirContext ctx = new InitialDirContext(props);
			Attributes atts = ctx.getAttributes("");
			Attribute a = atts.get("defaultNamingContext");
			if(a != null && a.get() != null) { // this entry is available on Active Directory. See http://msdn2.microsoft.com/en-us/library/ms684291(VS.85).aspx
				return a.get().toString();
			}

			a = atts.get("namingcontexts");
			if(a == null) {
				LOGGER.warning("namingcontexts attribute not found in root DSE of " + server);
				return null;
			}
			return a.get().toString();
		} catch (NamingException e) {
			LOGGER.log(Level.WARNING,"Failed to connect to LDAP to infer Root DN for "+server,e);
			return null;
		}
	}

	@Deprecated
	@Nullable
	public static String toProviderUrl(@CheckForNull String serverUrl, @CheckForNull String rootDN) {
		if (serverUrl == null) {
			return null;
		}
		StringBuilder buf = new StringBuilder();
		boolean first = true;
		for (String s: serverUrl.split("\\s+")) {
			if (s.trim().length() == 0) continue;
			if (first) first = false; else buf.append(' ');
			s = addPrefix(s);
			buf.append(s);
			if (!s.endsWith("/")) buf.append('/');
			buf.append(fixNull(rootDN));
		}
		return buf.toString();
	}

	@Deprecated
	public String getManagerPassword() {
		return Scrambler.descramble(managerPassword);
	}

	@Deprecated
	public int getUpdateInterval() {
		return updateInterval;
	}

	@Deprecated
	public String getLDAPURL() {
		return toProviderUrl(getServerUrl(), fixNull(rootDN));
	}

	@Override
	public Filter createFilter(FilterConfig filterConfig) {
		Filter filter = new Filter() {
			public void init(FilterConfig filterConfig) throws ServletException {
			}

			public void doFilter(ServletRequest request,
					ServletResponse response, FilterChain chain)
							throws IOException, ServletException {
				HttpServletRequest r = (HttpServletRequest) request;

			        String authorization = null;
				String userFromApiToken = null;
				if ((authorization = r.getHeader("Authorization")) != null && authorization.toLowerCase().startsWith("basic ")) {
					String uidpassword = Scrambler.descramble(authorization.substring(6));
					int idx = uidpassword.indexOf(':');
					if (idx >= 0) {
					        String username = uidpassword.substring(0, idx);
					        String password = uidpassword.substring(idx+1);

						// attempt to authenticate as API token
						User u = User.get(username, false);
						if (u != null) {
							ApiTokenProperty t = u.getProperty(ApiTokenProperty.class);
							if (t != null && t.matchesPassword(password)) {
							        userFromApiToken = username;
							}
						}
					}
				}

				String userFromHeader = null;

				Authentication auth = Jenkins.ANONYMOUS;
				if ((forwardedUser != null && (userFromHeader = r.getHeader(forwardedUser)) != null) || userFromApiToken != null) {
					LOGGER.log(Level.FINE, "USER LOGGED IN: {0}", userFromHeader);
			        if (userFromHeader == null) {
				        userFromHeader = userFromApiToken;
					}

					authorities = authorizationTypeMappingFactory.retrieveAuthorities(userFromHeader, r);
					auth = new UsernamePasswordAuthenticationToken(userFromHeader, "", authorities);
				}
				
				retrievedUser = userFromHeader;
				
				SecurityContextHolder.getContext().setAuthentication(auth);
				chain.doFilter(r, response);
			}

			public void destroy() {
			}
		};
		Filter defaultFilter = super.createFilter(filterConfig);
		return new ChainedServletFilter(defaultFilter, filter);
	}

	@Override
	public boolean canLogOut() {
		if (customLogOutUrl == null) {
			return false;
		} else {
			return true;
		}
	}

	@Override
	public String getPostLogOutUrl(StaplerRequest req, Authentication auth) {
		if (customLogOutUrl == null) {
			return super.getPostLogOutUrl(req, auth);
		} else {
			return customLogOutUrl;
		}
	}

	@Override
	public SecurityComponents createSecurityComponents() throws DataAccessException {
		Binding binding = new Binding();
		binding.setVariable("instance", this);
		binding.setVariable("instanceAuthorizationType", this.authorizationTypeMappingFactory);

		BeanBuilder builder = new BeanBuilder(Jenkins.getActiveInstance().pluginManager.uberClassLoader);

		String fileName = authorizationTypeMappingFactory.getFilename();

		File override = new File(Jenkins.getActiveInstance().getRootDir(), fileName);
		try(InputStream istream = override.exists()
				? new FileInputStream(override)
				: getClass().getResourceAsStream(fileName)) {
			if (istream == null) {
				throw new FileNotFoundException("Cannot find resource " + fileName);
			}
			builder.parse(istream, binding);
		} catch (IOException e) {
			// loadUserByUsername() declares DataAccessException to be thrown, so it is better than the Error which was thrown before 1.6.0
			throw new DataAccessResourceFailureException("Failed to load "+fileName, e);
		}
		WebApplicationContext appContext = builder.createApplicationContext();

		return authorizationTypeMappingFactory.createUserDetailService(appContext);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
		UserDetails userDetails = getSecurityComponents().userDetails.loadUserByUsername(username);
        return userDetails;
	}

	@Deprecated
    public LdapUserDetails updateLdapUserDetails(LdapUserDetails d) {
        LOGGER.log(Level.FINEST, "displayNameLdapAttribute" + displayNameLdapAttribute);
        LOGGER.log(Level.FINEST, "disableLdapEmailResolver" + disableLdapEmailResolver);
        LOGGER.log(Level.FINEST, "emailAddressLdapAttribute" + emailAddressLdapAttribute);
        if (d.getAttributes() == null){
            LOGGER.log(Level.FINEST, "getAttributes is null");
        } else {
            hudson.model.User u = hudson.model.User.get(d.getUsername());
            if (!StringUtils.isBlank(displayNameLdapAttribute)) {
                LOGGER.log(Level.FINEST, "Getting user details from LDAP attributes");
                try {
                    Attribute attribute = d.getAttributes().get(displayNameLdapAttribute);
                    String displayName = attribute == null ? null : (String) attribute.get();
                    LOGGER.log(Level.FINEST, "displayName is " + displayName);
                    if (StringUtils.isNotBlank(displayName)) {
                        u.setFullName(displayName);
                    }
                } catch (NamingException e) {
                    LOGGER.log(Level.FINEST, "Could not retrieve display name attribute", e);
                }
            }
            if (!disableLdapEmailResolver && !StringUtils.isBlank(emailAddressLdapAttribute)) {
                try {
                    Attribute attribute = d.getAttributes().get(emailAddressLdapAttribute);
                    String mailAddress = attribute == null ? null : (String) attribute.get();
                    if (StringUtils.isNotBlank(mailAddress)) {
                        LOGGER.log(Level.FINEST, "mailAddress is " + mailAddress);
                        UserProperty existing = u.getProperty(UserProperty.class);
                        if (existing == null || !existing.hasExplicitlyConfiguredAddress()){
                            LOGGER.log(Level.FINEST, "user mail address has been changed");
                            u.addProperty(new Mailer.UserProperty(mailAddress));
                        }
                    }
                } catch (NamingException e) {
                    LOGGER.log(Level.FINEST, "Could not retrieve email address attribute", e);
                } catch (IOException e) {
                    LOGGER.log(Level.WARNING, "Failed to associate the e-mail address", e);
                }
            }
        }
        return d;
    }

	@Override
	@SuppressWarnings("unchecked")
	public GroupDetails loadGroupByGroupname(String groupname) throws UsernameNotFoundException, DataAccessException {
		final Set<String> groups = authorizationTypeMappingFactory.loadGroupByGroupname(groupname);

		if(groups.isEmpty())
			throw new UsernameNotFoundException(groupname);

		return new GroupDetails() {
			@Override
			public String getName() {
				return groups.iterator().next();
			}
		};
	}

	public <T> T extractBean(Class<T> type, WebApplicationContext appContext) {
		T returnedObj = findBean(type, appContext);
		return returnedObj;
	}

	@Extension
	public static class ProxyLDAPDescriptor extends Descriptor<SecurityRealm> {

		@Override
		public String getDisplayName() {
			return Messages.ReverseProxySecurityRealm_DisplayName();
		}

	}

	public static class ReverseProxyUserDetailsService implements UserDetailsService {

		private final ReverseProxyAuthoritiesPopulator authoritiesPopulator;

		public ReverseProxyUserDetailsService(WebApplicationContext appContext) {
			authoritiesPopulator = findBean(
					ReverseProxyAuthoritiesPopulator.class, appContext);
		}

		public ReverseProxyUserDetails loadUserByUsername(String username)
				throws UsernameNotFoundException, DataAccessException {
			try {
				ReverseProxyUserDetails proxyUser = new ReverseProxyUserDetails();
				proxyUser.setUsername(username);

				GrantedAuthority[] localAuthorities = authoritiesPopulator.getGrantedAuthorities(proxyUser);

				proxyUser.setAuthorities(localAuthorities);

				return proxyUser;
			} catch (LdapDataAccessException e) {
				LOGGER.log(Level.WARNING, "Failed to search LDAP for username=" + username, e);
				throw new UserMayOrMayNotExistException(e.getMessage(), e);
			}
		}
	}

	@Deprecated
	private GrantedAuthority[] retrieveAuthoritiesIfNecessary(final String userFromHeader, final GrantedAuthority[] storedGrants) {
		
		GrantedAuthority[] authorities = storedGrants;
		
		if (getLDAPURL() != null) {
			
			long current = System.currentTimeMillis();
			if (authorityUpdateCache != null && authorityUpdateCache.containsKey(userFromHeader)) {
				long lastTime = authorityUpdateCache.get(userFromHeader);
				
				//Time in minutes since last occurrence
				long check = (current - lastTime) / 1000 / 60;
				if (check >= updateInterval) {
					
					LOGGER.log(Level.INFO, "The check interval reached the threshold of " + check + "min, will now update the authorities");
					
					LdapUserDetails userDetails = (LdapUserDetails) loadUserByUsername(userFromHeader);
					authorities = userDetails.getAuthorities();

					Set<GrantedAuthority> tempLocalAuthorities = new HashSet<GrantedAuthority>(Arrays.asList(authorities));
					tempLocalAuthorities.add(AUTHENTICATED_AUTHORITY);
					authorities = tempLocalAuthorities.toArray(new GrantedAuthority[0]);
					
					authorityUpdateCache.put(userFromHeader, current);
					
					LOGGER.log(Level.INFO, "Authorities for user " + userFromHeader + " have been updated.");
				}
			} else {
				if (authorityUpdateCache == null) {
					authorityUpdateCache = new Hashtable<String, Long>();
				}
				authorityUpdateCache.put(userFromHeader, current);
			}

		}
		
		return authorities;
	}
	
	/**
	 * If the given "server name" is just a host name (plus optional host name), add ldap:// prefix.
	 * Otherwise assume it already contains the scheme, and leave it intact.
	 */
	@Deprecated
	private static String addPrefix(String server) {
		if(server.contains("://"))  return server;
		else    return "ldap://"+server;
	}
}
