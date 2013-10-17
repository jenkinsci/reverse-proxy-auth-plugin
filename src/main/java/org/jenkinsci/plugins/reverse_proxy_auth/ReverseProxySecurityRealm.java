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

import static hudson.Util.fixEmptyAndTrim;
import static hudson.Util.fixNull;
import groovy.lang.Binding;
import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.Hudson;
import hudson.security.AbstractPasswordBasedSecurityRealm;
import hudson.security.AuthenticationManagerProxy;
import hudson.security.GroupDetails;
import hudson.security.LDAPSecurityRealm;
import hudson.security.SecurityRealm;
import hudson.security.UserMayOrMayNotExistException;
import hudson.util.spring.BeanBuilder;

import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.ldap.InitialDirContextFactory;
import org.acegisecurity.ldap.LdapDataAccessException;
import org.acegisecurity.ldap.LdapUserSearch;
import org.acegisecurity.providers.ProviderManager;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.providers.ldap.LdapAuthoritiesPopulator;
import org.acegisecurity.providers.ldap.populator.DefaultLdapAuthoritiesPopulator;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.acegisecurity.userdetails.ldap.LdapUserDetails;
import org.acegisecurity.userdetails.ldap.LdapUserDetailsImpl;
import org.kohsuke.stapler.DataBoundConstructor;
import org.springframework.dao.DataAccessException;
import org.springframework.web.context.WebApplicationContext;

import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttributes;
import javax.naming.ldap.Control;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.List;
import java.util.ArrayList;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import jenkins.model.Jenkins;

import org.apache.commons.collections.map.LRUMap;
import org.apache.commons.io.input.AutoCloseInputStream;
import org.apache.commons.lang.StringUtils;

/**
 * @author Kohsuke Kawaguchi
 */
public class ReverseProxySecurityRealm extends AbstractPasswordBasedSecurityRealm {

	private static final Logger LOGGER = Logger
			.getLogger(ReverseProxySecurityRealm.class.getName());

	/**
	 * LDAP filter to look for groups by their names.
	 * 
	 * "{0}" is the group name as given by the user. See
	 * http://msdn.microsoft.com/en-us/library/aa746475(VS.85).aspx for the
	 * syntax by example. WANTED: The specification of the syntax.
	 */
	public static String GROUP_SEARCH = System
			.getProperty(
					ReverseProxySecurityRealm.class.getName() + ".groupSearch",
					"(& (cn={0}) (| (objectclass=groupOfNames) (objectclass=groupOfUniqueNames) (objectclass=posixGroup)))");

	private final String header;
	private final String headerGroups;
	private final String headerGroupsDelimiter;

	/**
	 * Query to locate an entry that identifies the group, given the group name
	 * string. If non-null it will override the default specified by
	 * {@link #GROUP_SEARCH}
	 * 
	 * @since 1.5
	 */
	private final String groupSearchBase;
	private final String dn;

	private GrantedAuthority[] authorities;
	
	private final Hashtable<String, GrantedAuthority[]> authContext;

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
	public ReverseProxySecurityRealm(String header, String headerGroups, String headerGroupsDelimiter, String groupSearchBase, String dn) {
		this.header = header.trim();
		this.groupSearchBase = fixEmptyAndTrim(groupSearchBase);
		this.dn = fixEmptyAndTrim(dn);

		this.headerGroups = headerGroups;
		if (!StringUtils.isBlank(headerGroupsDelimiter)) {
			this.headerGroupsDelimiter = headerGroupsDelimiter.trim();
		} else {
			this.headerGroupsDelimiter = "|";
		}

		this.cache = null;
		authContext = new Hashtable<String, GrantedAuthority[]>();
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

	public String getGroupSearchBase() {
		return groupSearchBase;
	}

	public String getDn() {
		return dn;
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

	class AddParamsToHeader extends HttpServletRequestWrapper {
		public AddParamsToHeader(HttpServletRequest request) {
			super(request);
		}

		public String getHeader(String name) {
			Object header = super.getHeader(name);
			return (String) ((header != null) ? header : super
					.getAttribute(name));
		}

		public Enumeration getHeaderNames() {
			List<String> names = Collections.list(super.getHeaderNames());
			names.addAll(Collections.list(super.getAttributeNames()));
			return Collections.enumeration(names);
		}
	}

	@Override
	public Filter createFilter(FilterConfig filterConfig) {
		return new Filter() {
			public void init(FilterConfig filterConfig) throws ServletException {
			}

			public void doFilter(ServletRequest request,
					ServletResponse response, FilterChain chain)
					throws IOException, ServletException {
				HttpServletRequest r = (HttpServletRequest) request;

				String headerUsername = r.getHeader(header);
				if (headerUsername != null) {
					if (headerGroups != null) {
						String groups = r.getHeader(headerGroups);
						
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
						
						Authentication auth = new UsernamePasswordAuthenticationToken(headerUsername, "", authorities);
	
						SecurityContextHolder.getContext().setAuthentication(auth);
						
						authContext.put(headerUsername, authorities);
					}
				}
				chain.doFilter(r, response);
			}

			public void destroy() {
			}
		};
	}

	@Override
	public SecurityComponents createSecurityComponents() {
		super.createSecurityComponents();
		
		Binding binding = new Binding();
		binding.setVariable("instance", this);

		BeanBuilder builder = new BeanBuilder(Jenkins.getInstance().pluginManager.uberClassLoader);

		String fileName = "ReverseProxyBindSecurityRealm.groovy";
		try {
			File override = new File(Jenkins.getInstance().getRootDir(), fileName);
			builder.parse(override.exists() ? new AutoCloseInputStream( new FileInputStream(override)) : getClass().getResourceAsStream(fileName), binding);
		} catch (FileNotFoundException e) {
			throw new Error("Failed to load " + fileName, e);
		}

		WebApplicationContext appContext = builder.createApplicationContext();

		proxyTemplate = new ReverseProxySearchTemplate();
		
		return new SecurityComponents(findBean(AuthenticationManager.class,
				appContext), new ReverseProxyUserDetailsService(authContext));
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected UserDetails authenticate(String username, String password)
			throws AuthenticationException {
		
		// LOGGER.log(Level.INFO, "authenticate ==> username : {0}", username);

		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		return (UserDetails) auth.getPrincipal();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public UserDetails loadUserByUsername(String username)
			throws UsernameNotFoundException, DataAccessException {
		
		// LOGGER.log(Level.INFO, "loadUserByUsername ==> username : {0}", username);
		
		UserDetails ud = getSecurityComponents().userDetails.loadUserByUsername(username);
		
		// LOGGER.log(Level.INFO, "loadUserByUsername ==> authorities : {0}", ud.getAuthorities());
		
		return ud;
	}

	@Extension
	public static class DescriptorImpl extends Descriptor<SecurityRealm> {
		public String getDisplayName() {
			return Messages.ReverseProxySecurityRealm_DisplayName();
		}
	}

	@Override
	public GroupDetails loadGroupByGroupname(String groupname)
			throws UsernameNotFoundException, DataAccessException {

		// LOGGER.log(Level.INFO, "loadGroupByGroupname ==> groupName {0}", groupname);

		Set<String> cachedGroups;
		if (cache != null) {
			final CacheEntry<Set<String>> cached;
			synchronized (this) {
				cached = groupDetailsCache != null ? groupDetailsCache
						.get(groupname) : null;
			}
			if (cached != null && cached.isValid()) {
				cachedGroups = cached.getValue();
			} else {
				cachedGroups = null;
			}
		} else {
			cachedGroups = null;
		}

		// TODO: obtain a DN instead so that we can obtain multiple attributes
		// later
		String searchBase = groupSearchBase != null ? groupSearchBase : "";

		final Set<String> groups = cachedGroups != null ? cachedGroups
				: (Set<String>) proxyTemplate.searchForSingleAttributeValues(
						searchBase, authorities, groupname);

		if (cache != null && cachedGroups == null && !groups.isEmpty()) {
			synchronized (this) {
				if (groupDetailsCache == null) {
					groupDetailsCache = new CacheMap<String, Set<String>>(
							cache.getSize());
				}
				groupDetailsCache.put(groupname, new CacheEntry<Set<String>>(
						cache.getTtl(), groups));
			}
		}

		if (groups.isEmpty())
			throw new UsernameNotFoundException(groupname);

		return new GroupDetails() {
			public String getName() {
				return groups.iterator().next();
			}
		};
	}

	public static class ReverseProxyUserDetailsService implements
			UserDetailsService {

		private Hashtable<String, GrantedAuthority[]> authContext;

		public ReverseProxyUserDetailsService(Hashtable<String, GrantedAuthority[]> authContext) {
			this.authContext = authContext;
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
							cached = (proxySecurityRealm.userDetailsCache != null) ? proxySecurityRealm.userDetailsCache
									.get(username) : null;
						}
						if (cached != null && cached.isValid()) {
							return cached.getValue();
						}
					}
				}
				
				GrantedAuthority[] localAuthorities = authContext.get(username);
				
				// LOGGER.log(Level.INFO, "loadGroupByGroupname ==> AUTHORITIES {0}", localAuthorities);
				
				ReverseProxyUserDetails proxyUser = new ReverseProxyUserDetails();
				proxyUser.setUsername(username);
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
							proxySecurityRealm.userDetailsCache.put(
									username,
									new CacheEntry<ReverseProxyUserDetails>(
											proxySecurityRealm.cache.getTtl(),
											proxyUser));
						}
					}
				}

				return proxyUser;
			} catch (LdapDataAccessException e) {
				LOGGER.log(Level.WARNING, "Failed to search LDAP for username="
						+ username, e);
				throw new UserMayOrMayNotExistException(e.getMessage(), e);
			}
		}
	}
	
	public static class ReverseProxyUserDetails implements UserDetails {

		private static Attributes attributes = new BasicAttributes();

		private GrantedAuthority[] authorities;
		private String username;
		private String dn;

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
			this.expires = System.currentTimeMillis()
					+ TimeUnit.SECONDS.toMillis(ttlSeconds);
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
}