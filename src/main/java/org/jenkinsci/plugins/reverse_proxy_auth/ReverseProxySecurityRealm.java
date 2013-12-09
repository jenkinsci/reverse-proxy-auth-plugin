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

import groovy.lang.Binding;
import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.Hudson;
import hudson.security.GroupDetails;
import hudson.security.UserMayOrMayNotExistException;
import hudson.security.SecurityRealm;
import hudson.util.spring.BeanBuilder;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttributes;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import jenkins.model.Jenkins;

import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.ldap.LdapDataAccessException;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.apache.commons.io.input.AutoCloseInputStream;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.plugins.reverse_proxy_auth.auth.DefaultReverseProxyAuthoritiesPopulator;
import org.jenkinsci.plugins.reverse_proxy_auth.auth.ReverseProxyAuthoritiesPopulator;
import org.jenkinsci.plugins.reverse_proxy_auth.data.GroupSearchTemplate;
import org.jenkinsci.plugins.reverse_proxy_auth.data.SearchTemplate;
import org.jenkinsci.plugins.reverse_proxy_auth.data.UserSearchTemplate;
import org.kohsuke.stapler.DataBoundConstructor;
import org.springframework.dao.DataAccessException;
import org.springframework.web.context.WebApplicationContext;

/**
 * @author Kohsuke Kawaguchi
 */
public class ReverseProxySecurityRealm extends SecurityRealm {

	private static final Logger LOGGER = Logger
			.getLogger(ReverseProxySecurityRealm.class.getName());

	public final String header;
	public final String headerGroups;
	public final String headerGroupsDelimiter;

	public String retrievedUsername;

	public GrantedAuthority[] authorities;

	public Hashtable<String, GrantedAuthority[]> authContext;
	/**
	 * The cache configuration
	 * 
	 * @since 1.3
	 */
	private final CacheConfiguration cache;

	private ReverseProxySearchTemplate proxyTemplate;

	/**
	 * The {@link UserDetails} cache.
	 */
	private transient Map<String, CacheEntry<ReverseProxyUserDetails>> userDetailsCache = null;

	/**
	 * The group details cache.
	 */
	private transient Map<String, CacheEntry<Set<String>>> groupDetailsCache = null;

	@DataBoundConstructor
	public ReverseProxySecurityRealm(String header, String headerGroups,
			String headerGroupsDelimiter) {
		this.header = header.trim();

		this.headerGroups = headerGroups;
		if (!StringUtils.isBlank(headerGroupsDelimiter)) {
			this.headerGroupsDelimiter = headerGroupsDelimiter.trim();
		} else {
			this.headerGroupsDelimiter = "|";
		}

		cache = null;
		authContext = new Hashtable<String, GrantedAuthority[]>();
		authorities = new GrantedAuthority[0];
	}

	/**
	 * Name of the HTTP header to look at.
	 */
	public String getHeader() {
		return header;
	}

	public String getHeaderGroups() {
		return headerGroups;
	}

	public String getHeaderGroupsDelimiter() {
		return headerGroupsDelimiter;
	}

	@Override
	public boolean canLogOut() {
		return false;
	}

	public CacheConfiguration getCache() {
		return cache;
	}

	public Integer getCacheSize() {
		return cache == null ? null : cache.getSize();
	}

	public Integer getCacheTTL() {
		return cache == null ? null : cache.getTtl();
	}

	@Override
	public Filter createFilter(FilterConfig filterConfig) {
		return new Filter() {
			public void init(FilterConfig filterConfig) throws ServletException {
			}

			@SuppressWarnings("unused")
			public void doFilter(ServletRequest request,
					ServletResponse response, FilterChain chain)
							throws IOException, ServletException {
				HttpServletRequest r = (HttpServletRequest) request;

				String headerUsername = r.getHeader(header);
				retrievedUsername = headerUsername;

				Authentication auth;
				if (headerGroups != null) {
					if (headerUsername == null) {
						auth = Hudson.ANONYMOUS;
					} else {
						String groups = r.getHeader(headerGroups);
						LOGGER.log(Level.INFO, "USER LOGGED IN: {0}", headerUsername);
						LOGGER.log(Level.INFO, "USER GROUPS: {0}", groups);

						List<GrantedAuthority> localAuthorities = new ArrayList<GrantedAuthority>();
						localAuthorities.add(AUTHENTICATED_AUTHORITY);

						if (groups != null) {
							StringTokenizer tokenizer = new StringTokenizer(groups, headerGroupsDelimiter);
							while (tokenizer.hasMoreTokens()) {
								final String token = tokenizer.nextToken().trim();
								// String[] args = new String[] { token, username };
								// LOGGER.log(Level.INFO, "granting: {0} to {1}", args);
								localAuthorities.add(new GrantedAuthorityImpl(token));
							}
						}

						authorities = localAuthorities.toArray(new GrantedAuthority[0]);

						SearchTemplate searchTemplate = new UserSearchTemplate(headerUsername);

						Set<String> foundAuthorities = proxyTemplate.searchForSingleAttributeValues(searchTemplate, authorities);
						Set<GrantedAuthority> tempLocalAuthorities = new HashSet<GrantedAuthority>();

						String[] authString = foundAuthorities.toArray(new String[0]);
						for (int i = 0; i < authString.length; i++) {
							tempLocalAuthorities.add(new GrantedAuthorityImpl(authString[i]));
						}

						authorities = tempLocalAuthorities.toArray(new GrantedAuthority[0]);
						authContext.put(headerUsername, authorities);

						auth = new UsernamePasswordAuthenticationToken(headerUsername, "", authorities);
					}
					SecurityContextHolder.getContext().setAuthentication(auth);
					chain.doFilter(r, response);
				}
			}

			public void destroy() {
			}
		};
	}

	@Override
	public SecurityComponents createSecurityComponents() {
		Binding binding = new Binding();
		binding.setVariable("instance", this);

		BeanBuilder builder = new BeanBuilder(Jenkins.getInstance().pluginManager.uberClassLoader);

		String fileName = "ReverseProxyBindSecurityRealm.groovy";
		try {
			File override = new File(Jenkins.getInstance().getRootDir(), fileName);
			builder.parse(override.exists() ? new AutoCloseInputStream( new FileInputStream(override)) : getClass()
					.getResourceAsStream(fileName), binding);
		} catch (FileNotFoundException e) {
			throw new Error("Failed to load " + fileName, e);
		}

		WebApplicationContext appContext = builder.createApplicationContext();

		proxyTemplate = new ReverseProxySearchTemplate();

		return new SecurityComponents(findBean(AuthenticationManager.class,
				appContext), new ReverseProxyUserDetailsService(appContext));
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public UserDetails loadUserByUsername(String username)
			throws UsernameNotFoundException, DataAccessException {

		UserDetails ud = getSecurityComponents().userDetails.loadUserByUsername(username);

		return ud;
	}

	@Extension
	public static class DescriptorImpl extends Descriptor<SecurityRealm> {
		@Override
		public String getDisplayName() {
			return Messages.ReverseProxySecurityRealm_DisplayName();
		}
	}

	@Override
	public GroupDetails loadGroupByGroupname(String groupname)
			throws UsernameNotFoundException, DataAccessException {

		Set<String> cachedGroups = null;
		if (cache != null) {
			final CacheEntry<Set<String>> cached;
			synchronized (this) {
				cached = groupDetailsCache != null ? groupDetailsCache.get(groupname) : null;
			}
			if (cached != null && cached.isValid()) {
				cachedGroups = cached.getValue();
			} else {
				cachedGroups = null;
			}
		} else {
			cachedGroups = null;
		}

		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		GrantedAuthority[] authorities = authContext.get(auth.getName());

		SearchTemplate searchTemplate = new GroupSearchTemplate(groupname);

		final Set<String> groups = cachedGroups != null ? cachedGroups
				: proxyTemplate.searchForSingleAttributeValues(searchTemplate,
						authorities);

		if (cache != null && cachedGroups == null && !groups.isEmpty()) {
			synchronized (this) {
				if (groupDetailsCache == null) {
					groupDetailsCache = new CacheMap<String, Set<String>>(cache.getSize());
				}
				groupDetailsCache.put(groupname, new CacheEntry<Set<String>>(cache.getTtl(), groups));
			}
		}

		if (groups.isEmpty())
			throw new UsernameNotFoundException(groupname);

		return new GroupDetails() {
			@Override
			public String getName() {
				return groups.iterator().next();
			}
		};
	}

	public static class ReverseProxyUserDetailsService implements
	UserDetailsService {

		private final ReverseProxyAuthoritiesPopulator authoritiesPopulator;

		public ReverseProxyUserDetailsService(WebApplicationContext appContext) {
			authoritiesPopulator = findBean(
					ReverseProxyAuthoritiesPopulator.class, appContext);
		}

		public ReverseProxyUserDetails loadUserByUsername(String username)
				throws UsernameNotFoundException, DataAccessException {
			try {
				SecurityRealm securityRealm = Jenkins.getInstance() == null ? null
						: Jenkins.getInstance().getSecurityRealm();

				if (securityRealm instanceof ReverseProxySecurityRealm
						&& securityRealm.getSecurityComponents().userDetails == this) {

					ReverseProxySecurityRealm proxySecurityRealm = (ReverseProxySecurityRealm) securityRealm;

					if (proxySecurityRealm.cache != null) {
						final CacheEntry<ReverseProxyUserDetails> cached;
						synchronized (proxySecurityRealm) {
							cached = proxySecurityRealm.userDetailsCache != null ? proxySecurityRealm.userDetailsCache.get(username) : null;
						}
						if (cached != null && cached.isValid()) {
							return cached.getValue();
						}
					}
				}

				ReverseProxyUserDetails proxyUser = new ReverseProxyUserDetails();
				proxyUser.setUsername(username);

				GrantedAuthority[] localAuthorities = authoritiesPopulator
						.getGrantedAuthorities(proxyUser);

				proxyUser.setAuthorities(localAuthorities);

				if (securityRealm instanceof ReverseProxySecurityRealm
						&& securityRealm.getSecurityComponents().userDetails == this) {

					ReverseProxySecurityRealm proxySecurityRealm = (ReverseProxySecurityRealm) securityRealm;

					if (proxySecurityRealm.cache != null) {
						synchronized (proxySecurityRealm) {
							if (proxySecurityRealm.userDetailsCache == null) {
								proxySecurityRealm.userDetailsCache = new CacheMap<String, ReverseProxyUserDetails>(
										proxySecurityRealm.cache.getSize());
							}
							proxySecurityRealm.userDetailsCache.put(username,
									new CacheEntry<ReverseProxyUserDetails>(proxySecurityRealm.cache.getTtl(), proxyUser));
						}
					}
				}

				return proxyUser;
			} catch (LdapDataAccessException e) {
				LOGGER.log(Level.WARNING, "Failed to search LDAP for username=" + username, e);
				throw new UserMayOrMayNotExistException(e.getMessage(), e);
			}
		}
	}

	/**
	 * {@link ReverseProxyAuthoritiesPopulator} that adds the automatic
	 * 'authenticated' role.
	 */
	public static final class ReverseProxyAuthoritiesPopulatorImpl extends
	DefaultReverseProxyAuthoritiesPopulator {

		String rolePrefix = "ROLE_";
		boolean convertToUpperCase = true;

		public ReverseProxyAuthoritiesPopulatorImpl(
				Hashtable<String, GrantedAuthority[]> authContext) {
			super(authContext);

			super.setRolePrefix("");
			super.setConvertToUpperCase(false);
		}

		@Override
		protected Set<GrantedAuthority> getAdditionalRoles(
				ReverseProxyUserDetails proxyUser) {
			return Collections.singleton(AUTHENTICATED_AUTHORITY);
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

			Set<GrantedAuthority> names = super
					.getGroupMembershipRoles(username);

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

	public static class ReverseProxyUserDetails implements UserDetails {

		private static final long serialVersionUID = 8070729070782792157L;

		private static Attributes attributes = new BasicAttributes();

		private GrantedAuthority[] authorities;
		private String username;

		public GrantedAuthority[] getAuthorities() {
			return authorities;
		}

		public void setAuthorities(GrantedAuthority[] authorities) {
			this.authorities = authorities;
		}

		public String getPassword() {
			return "";
		}

		public String getUsername() {
			return username;
		}

		public void setUsername(String username) {
			this.username = username;
		}

		public boolean isAccountNonExpired() {
			return true;
		}

		public boolean isAccountNonLocked() {
			return true;
		}

		public boolean isCredentialsNonExpired() {
			return true;
		}

		public boolean isEnabled() {
			return true;
		}

		public Attributes getAttributes() {
			return attributes;
		}
	}

	public static class CacheConfiguration {
		private final int size;
		private final int ttl;

		@DataBoundConstructor
		public CacheConfiguration(int size, int ttl) {
			this.size = Math.max(10, Math.min(size, 1000));
			this.ttl = Math.max(30, Math.min(ttl, 3600));
		}

		public int getSize() {
			return size;
		}

		public int getTtl() {
			return ttl;
		}
	}

	private static class CacheEntry<T> {
		private final long expires;
		private final T value;

		public CacheEntry(int ttlSeconds, T value) {
			this.expires = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(ttlSeconds);
			this.value = value;
		}

		public T getValue() {
			return value;
		}

		public boolean isValid() {
			return System.currentTimeMillis() < expires;
		}
	}

	/**
	 * While we could use Guava's CacheBuilder the method signature changes make
	 * using it problematic. Safer to roll our own and ensure compatibility
	 * across as wide a range of Jenkins versions as possible.
	 * 
	 * @param <K>
	 *            Key type
	 * @param <V>
	 *            Cache entry type
	 */
	private static class CacheMap<K, V> extends LinkedHashMap<K, CacheEntry<V>> {

		private final int cacheSize;

		public CacheMap(int cacheSize) {
			super(cacheSize + 1); // prevent realloc when hitting cache size
			// limit
			this.cacheSize = cacheSize;
		}

		@Override
		protected boolean removeEldestEntry(Map.Entry<K, CacheEntry<V>> eldest) {
			return size() > cacheSize || eldest.getValue() == null
					|| !eldest.getValue().isValid();
		}
	}

	static String headers = "CN=ALIAS-Beyond-Cupfighting,OU=ALIAS,OU=Distribution Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=AMS-CORP-Com,OU=AMS,OU=Distribution Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=AMS-CORP-Everyone,OU=AMS,OU=Distribution Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=AMS-CORP-Mission_critical_engineering,OU=AMS,OU=Distribution Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=AMS-CORP-Sales,OU=AMS,OU=Distribution Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=APP_ABW_Acceptance,OU=Application Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=APP_ABW_Development,OU=Application Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=APP_Agresso_User,OU=Application Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=APP_Confluence_Admin,OU=Application Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=APP_Confluence_M,OU=Application Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=APP_Confluence_User,OU=Application Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=APP_Connect_Admin,OU=Application Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=APP_Coveo_Admin,OU=Application Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=APP_GitHub_Admin,OU=Application Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=APP_Jira_Admin,OU=Application Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=APP_Jira_User,OU=Application Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=APP_SAS_SBP_SMSToken,OU=Application Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=APP_SBP_TeamAdmin_Admin,OU=Application Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=APP_Tableau_Admin,OU=Application Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=COMP_SBP,OU=Company Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=CUST_SBP,OU=Customer Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=CUST_SEC,OU=Customer Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=CUST_SUM,OU=Customer Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=CUST_TKT,OU=Customer Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=DB_AgressoPRD_R,OU=Database Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=DB_Confluence_R,OU=Database Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=DB_Easy2Comply_R,OU=Database Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=DB_Monitor247_R,OU=Database Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=DB_Reporting_M,OU=Database Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=DB_Reporting_R,OU=Database Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=DB_SBPResourcing_M,OU=Database Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=DB_SBPResourcing_R,OU=Database Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=ext-eduscrum,OU=EXT,OU=Distribution Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=FMG_Int_Cloud,OU=Functional Mailbox Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=FMG_Int_Connect,OU=Functional Mailbox Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=FMG_Int_Corpit,OU=Functional Mailbox Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=FMG_Int_Loodswezen,OU=Functional Mailbox Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=FMG_int_splunk,OU=Functional Mailbox Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=FMG_Int_Toolkit,OU=Functional Mailbox Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=FMG_Mon_Corpit,OU=Functional Mailbox Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=FMG_x_cvs_commits,OU=Functional Mailbox Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=FS_Business_BiMonthlyTeamMeetings_M,OU=Filesystem Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=int-abw,OU=INT,OU=Distribution Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=int-apptoolkit,OU=INT,OU=Distribution Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=int-bladelogic,OU=INT,OU=Distribution Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=int-bloggers,OU=INT,OU=Distribution Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=int-cloud,OU=INT,OU=Distribution Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=int-connect,OU=INT,OU=Distribution Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=int-fixit,OU=INT,OU=Distribution Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=int-greenkit,OU=INT,OU=Distribution Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=int-intranet,OU=INT,OU=Distribution Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=int-knowledgemanagement,OU=INT,OU=Distribution Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=int-lead-security,OU=INT,OU=Distribution Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=int-multivers,OU=INT,OU=Distribution Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=int-recruitment,OU=INT,OU=Distribution Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=int-sbb,OU=INT,OU=Distribution Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=int-scrum,OU=INT,OU=Distribution Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=int-splunk,OU=INT,OU=Distribution Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=int-summit,OU=INT,OU=Distribution Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=int-tooling,OU=INT,OU=Distribution Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=int-vdi,OU=INT,OU=Distribution Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=int-WSUS-testers,OU=INT,OU=Distribution Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=itsec-jira,OU=legacy,OU=Distribution Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=oneXUser,OU=SBP Security Groups,DC=sbp,DC=lan|CN=RG_MigratedHomeDir,OU=Resource Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=RL_COM,OU=Role Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=RL_Sales,OU=Role Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=RL_WSUSTesters,OU=Role Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=SBP-AMS-Citrix Users,OU=Legacy Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=SBP-AMS-Citrix-ABW-Acceptance,OU=Citrix Applications,OU=Legacy Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=SBP-AMS-Citrix-ABW-Development,OU=Citrix Applications,OU=Legacy Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=SBP-AMS-Confluence_acc-DB-ReadOnly,OU=Legacy Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=SBP-AMS-Confluence_prod-DB-ReadOnly,OU=Legacy Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=SBP-AMS-ConfluenceAdmin,OU=Legacy Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=SBP-AMS-Everyone,OU=Legacy Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=SBP-AMS-IM247DB-ReadOnly,OU=Legacy Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=SBP-AMS-Intranet,OU=Legacy Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=SBP-AMS-PILOT,OU=Legacy Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=SBP-AMS-ProjectManagers,OU=Legacy Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=SBP-AMS-Sales,OU=Legacy Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=SBP-AMS-SalesPrinter,OU=Legacy Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=SBP-AMS-TableauAdmin,OU=Legacy Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=SBP-AMS-TEMPLATES_1,OU=Legacy Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=SBP-AMS-TEST_HuisstijlUpdate,OU=Legacy Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=SBP-AMS-VPN-McInfra,OU=Legacy Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=SBP-AMS-WSUSTesters,OU=Legacy Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=SEC_ARACCAdmins,OU=Security Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=SEC_ARDEVAdmins,OU=Security Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=sme-banking,OU=SME,OU=Distribution Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=x-geeks,OU=X,OU=Distribution Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=x-geeks-mac,OU=X,OU=Distribution Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=x-hackalong,OU=X,OU=Distribution Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=x-hackerspace,OU=X,OU=Distribution Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=x-ipad,OU=X,OU=Distribution Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=x-postsummit,OU=X,OU=Distribution Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=x-running,OU=X,OU=Distribution Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan|CN=x-swim,OU=X,OU=Distribution Groups,OU=Groups,OU=CORPIT,DC=sbp,DC=lan";
}