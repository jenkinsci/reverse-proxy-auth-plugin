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

import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.security.*;
import hudson.tasks.Mailer;
import hudson.tasks.Mailer.UserProperty;
import hudson.util.FormValidation;
import hudson.util.Scrambler;
import hudson.util.Secret;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
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
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.ldap.DefaultInitialDirContextFactory;
import org.acegisecurity.ldap.LdapDataAccessException;
import org.acegisecurity.ldap.LdapTemplate;
import org.acegisecurity.ldap.search.FilterBasedLdapUserSearch;
import org.acegisecurity.providers.AuthenticationProvider;
import org.acegisecurity.providers.ProviderManager;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.providers.anonymous.AnonymousAuthenticationProvider;
import org.acegisecurity.providers.ldap.LdapAuthenticationProvider;
import org.acegisecurity.providers.ldap.authenticator.BindAuthenticator2;
import org.acegisecurity.providers.rememberme.RememberMeAuthenticationProvider;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.acegisecurity.userdetails.ldap.LdapUserDetails;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.plugins.reverse_proxy_auth.auth.DefaultReverseProxyAuthenticator;
import org.jenkinsci.plugins.reverse_proxy_auth.auth.ReverseProxyAuthenticationProvider;
import org.jenkinsci.plugins.reverse_proxy_auth.auth.ReverseProxyAuthoritiesPopulator;
import org.jenkinsci.plugins.reverse_proxy_auth.auth.ReverseProxyAuthoritiesPopulatorImpl;
import org.jenkinsci.plugins.reverse_proxy_auth.data.GroupSearchTemplate;
import org.jenkinsci.plugins.reverse_proxy_auth.data.SearchTemplate;
import org.jenkinsci.plugins.reverse_proxy_auth.data.UserSearchTemplate;
import org.jenkinsci.plugins.reverse_proxy_auth.model.ReverseProxyUserDetails;
import org.jenkinsci.plugins.reverse_proxy_auth.service.ProxyLDAPAuthoritiesPopulator;
import org.jenkinsci.plugins.reverse_proxy_auth.service.ProxyLDAPUserDetailsService;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.verb.POST;
import org.springframework.dao.DataAccessException;

/**
 * @author Kohsuke Kawaguchi
 */
public class ReverseProxySecurityRealm extends SecurityRealm {

  private static final Logger LOGGER = Logger.getLogger(ReverseProxySecurityRealm.class.getName());

  /**
   * LDAP filter to look for groups by their names.
   *
   * <p>"{0}" is the group name as given by the user. See
   * http://msdn.microsoft.com/en-us/library/aa746475(VS.85).aspx for the syntax by example. WANTED:
   * The specification of the syntax.
   */
  @SuppressFBWarnings(
      value = "MS_SHOULD_BE_FINAL",
      justification = "May be used in system groovy scripts")
  public static String GROUP_SEARCH =
      System.getProperty(
          "hudson.security.LDAPSecurityRealm.groupSearch",
          "(& (cn={0}) (| (objectclass=groupOfNames) (objectclass=groupOfUniqueNames)"
              + " (objectclass=posixGroup)))");

  /** Interval to check user authorities via LDAP. */
  private static final int CHECK_INTERVAL = 15;

  /** Encrypted password, used to first bind to LDAP. */
  private Secret managerPasswordSecret;

  /** Scrambled password, used to migrate from string to secret. */
  @Deprecated private transient String managerPassword;

  /** Search Template used when the groups are in the header. */
  private ReverseProxySearchTemplate proxyTemplate;

  /** Created in {@link #createSecurityComponents()}. Can be used to connect to LDAP. */
  private transient LdapTemplate ldapTemplate;

  /** Keeps the state of connected users and their granted authorities. */
  private transient Hashtable<String, GrantedAuthority[]> authContext;

  /**
   * Keeps the frequency which the authorities cache is updated per connected user. The types String
   * and Long are used for username and last time checked (in minutes) respectively.
   */
  private transient Hashtable<String, Long> authorityUpdateCache;

  /**
   * LDAP server name(s) separated by spaces, optionally with TCP port number, like "ldap.acme.org"
   * or "ldap.acme.org:389" and/or with protcol, like "ldap://ldap.acme.org".
   */
  public final String server;

  /**
   * The root DN to connect to. Normally something like "dc=sun,dc=com"
   *
   * <p>How do I infer this?
   */
  public final String rootDN;

  /** Allow the rootDN to be inferred? Default is false. If true, allow rootDN to be blank. */
  public final boolean inhibitInferRootDN;

  /**
   * Specifies the relative DN from {@link #rootDN the root DN}. This is used to narrow down the
   * search space when doing user search.
   *
   * <p>Something like "ou=people" but can be empty.
   */
  public final String userSearchBase;

  /**
   * Query to locate an entry that identifies the user, given the user name string.
   *
   * <p>Normally "uid={0}"
   *
   * @see FilterBasedLdapUserSearch
   */
  public final String userSearch;

  /**
   * This defines the organizational unit that contains groups.
   *
   * <p>Normally "" to indicate the full LDAP search, but can be often narrowed down to something
   * like "ou=groups"
   *
   * @see FilterBasedLdapUserSearch
   */
  public final String groupSearchBase;

  /**
   * Query to locate an entry that identifies the group, given the group name string. If non-null it
   * will override the default specified by {@link #GROUP_SEARCH}
   *
   * @since 1.5
   */
  public final String groupSearchFilter;

  /**
   * Query to locate the group entries that a user belongs to, given the user object. <code>{0}
   * </code> is the user's full DN while {1} is the username.
   */
  public final String groupMembershipFilter;

  /**
   * Attribute that should be used instead of CN as name to match a users group name to the
   * groupSearchFilter name. When {@link #groupSearchFilter} is set to search for a field other than
   * CN e.g. <code>GroupDisplayName={0}</code> here you can configure that this (<code>
   * GroupDisplayName</code>) or another field should be used when looking for a users groups.
   */
  public String groupNameAttribute;

  /**
   * If non-null, we use this and {@link #managerPasswordSecret} when binding to LDAP.
   *
   * <p>This is necessary when LDAP doesn't support anonymous access.
   */
  public final String managerDN;

  /** Sets an interval for updating the LDAP authorities. The interval is specified in minutes. */
  public final int updateInterval;

  /**
   * The authorities that are granted to the authenticated user. It is not necessary, that the
   * authorities will be stored in the config.xml, they blow up the config.xml
   */
  public transient GrantedAuthority[] authorities = new GrantedAuthority[0];

  /** The name of the header which the username has to be extracted from. */
  @CheckForNull public final String forwardedUser;

  /**
   * The username retrieved from the header field, which is represented by the forwardedUser
   * attribute.
   */
  public String retrievedUser;

  /** Header name of the groups field. */
  public final String headerGroups;

  /** Header name of the groups delimiter field. */
  public final String headerGroupsDelimiter;

  public final boolean disableLdapEmailResolver;

  private final String displayNameLdapAttribute;

  private final String emailAddressLdapAttribute;

  /** Custom post logout url */
  public final String customLogInUrl;

  public final String customLogOutUrl;

  @DataBoundConstructor
  public ReverseProxySecurityRealm(
      String forwardedUser,
      String headerGroups,
      String headerGroupsDelimiter,
      String customLogInUrl,
      String customLogOutUrl,
      String server,
      String rootDN,
      boolean inhibitInferRootDN,
      String userSearchBase,
      String userSearch,
      String groupSearchBase,
      String groupSearchFilter,
      String groupMembershipFilter,
      String groupNameAttribute,
      String managerDN,
      Secret managerPassword,
      Integer updateInterval,
      boolean disableLdapEmailResolver,
      String displayNameLdapAttribute,
      String emailAddressLdapAttribute) {

    this.forwardedUser = fixEmptyAndTrim(forwardedUser);

    this.headerGroups = headerGroups;
    if (!StringUtils.isBlank(headerGroupsDelimiter)) {
      this.headerGroupsDelimiter = headerGroupsDelimiter.trim();
    } else {
      this.headerGroupsDelimiter = "|";
    }

    if (!StringUtils.isBlank(customLogInUrl)) {
      this.customLogInUrl = customLogInUrl;
    } else {
      this.customLogInUrl = null;
    }

    if (!StringUtils.isBlank(customLogOutUrl)) {
      this.customLogOutUrl = customLogOutUrl;
    } else {
      this.customLogOutUrl = null;
    }

    this.server = fixEmptyAndTrim(server);
    this.managerDN = fixEmpty(managerDN);
    this.managerPasswordSecret = managerPassword;
    this.inhibitInferRootDN = inhibitInferRootDN;

    if (this.server != null) {
      if (!inhibitInferRootDN && fixEmptyAndTrim(rootDN) == null)
        rootDN = fixNull(inferRootDN(server));
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

    this.updateInterval =
        (updateInterval == null || updateInterval <= 0) ? CHECK_INTERVAL : updateInterval;

    authorities = new GrantedAuthority[0];

    this.disableLdapEmailResolver = disableLdapEmailResolver;
    this.displayNameLdapAttribute = displayNameLdapAttribute;
    this.emailAddressLdapAttribute = emailAddressLdapAttribute;
  }

  /** Name of the HTTP header to look at. */
  public String getForwardedUser() {
    return forwardedUser;
  }

  public String getHeaderGroups() {
    return headerGroups;
  }

  public String getHeaderGroupsDelimiter() {
    return headerGroupsDelimiter;
  }

  @CheckForNull
  public String getServerUrl() {
    if (server == null) {
      return null;
    }
    StringBuilder buf = new StringBuilder();
    boolean first = true;

    for (String s : server.split("\\s+")) {
      if (s.trim().length() == 0) continue;
      if (first) first = false;
      else buf.append(' ');
      buf.append(addPrefix(s));
    }
    return buf.toString();
  }

  public String getGroupSearchFilter() {
    return groupSearchFilter;
  }

  public String getGroupMembershipFilter() {
    return groupMembershipFilter;
  }

  public String getGroupNameAttribute() {
    return groupNameAttribute;
  }

  public void setGroupNameAttribute(String groupNameAttribute) {
    this.groupNameAttribute = groupNameAttribute;
  }

  public String getDisplayNameLdapAttribute() {
    return displayNameLdapAttribute;
  }

  public String getEmailAddressLdapAttribute() {
    return emailAddressLdapAttribute;
  }

  protected Object readResolve() {
    if (this.managerPassword != null) {
      this.managerPasswordSecret = Secret.fromString(Scrambler.descramble(this.managerPassword));
    }
    return this;
  }

  /**
   * Infer the root DN.
   *
   * @return null if not found.
   */
  private String inferRootDN(String server) {
    try {
      Hashtable<String, String> props = new Hashtable<String, String>();
      if (managerDN != null && getManagerPassword() != null) {
        props.put(Context.SECURITY_PRINCIPAL, managerDN);
        props.put(Context.SECURITY_CREDENTIALS, getManagerPassword().getPlainText());
      }
      props.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
      // TODO: should it pass null instead and check the result?
      props.put(Context.PROVIDER_URL, toProviderUrl(fixNull(getServerUrl()), ""));

      DirContext ctx = new InitialDirContext(props);
      Attributes atts = ctx.getAttributes("");
      Attribute a = atts.get("defaultNamingContext");
      if (a != null && a.get() != null) { // this entry is available on Active Directory. See
        // http://msdn2.microsoft.com/en-us/library/ms684291(VS.85).aspx
        return a.get().toString();
      }

      a = atts.get("namingcontexts");
      if (a == null) {
        LOGGER.warning("namingcontexts attribute not found in root DSE of " + server);
        return null;
      }
      return a.get().toString();
    } catch (NamingException e) {
      LOGGER.log(Level.WARNING, "Failed to connect to LDAP to infer Root DN for " + server, e);
      return null;
    }
  }

  @Nullable
  public static String toProviderUrl(@CheckForNull String serverUrl, @CheckForNull String rootDN) {
    if (serverUrl == null) {
      return null;
    }
    StringBuilder buf = new StringBuilder();
    boolean first = true;
    for (String s : serverUrl.split("\\s+")) {
      if (s.trim().length() == 0) continue;
      if (first) first = false;
      else buf.append(' ');
      s = addPrefix(s);
      buf.append(s);
      if (!s.endsWith("/")) buf.append('/');
      buf.append(fixNull(rootDN));
    }
    return buf.toString();
  }

  public Secret getManagerPassword() {
    return managerPasswordSecret;
  }

  public int getUpdateInterval() {
    return updateInterval;
  }

  public String getLDAPURL() {
    return toProviderUrl(getServerUrl(), fixNull(rootDN));
  }

  @Override
  public Filter createFilter(FilterConfig filterConfig) {
    Filter filter =
        new Filter() {
          public void init(FilterConfig filterConfig) throws ServletException {}

          public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
              throws IOException, ServletException {
            HttpServletRequest r = (HttpServletRequest) request;

            String authorization = null;
            String userFromApiToken = null;
            if ((authorization = r.getHeader("Authorization")) != null
                && authorization.toLowerCase().startsWith("basic ")) {
              String uidpassword = Scrambler.descramble(authorization.substring(6));
              int idx = uidpassword.indexOf(':');
              if (idx >= 0) {
                String username = uidpassword.substring(0, idx);
                String password = uidpassword.substring(idx + 1);

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
            if ((forwardedUser != null && (userFromHeader = r.getHeader(forwardedUser)) != null)
                || userFromApiToken != null) {
              LOGGER.log(Level.FINE, "USER LOGGED IN: {0}", userFromHeader);
              if (userFromHeader == null) {
                userFromHeader = userFromApiToken;
              }

              if (authContext == null) {
                authContext = new Hashtable<>();
              }

              if (getLDAPURL() != null) {

                GrantedAuthority[] storedGrants = authContext.get(userFromHeader);
                if (storedGrants != null && storedGrants.length > 1) {
                  authorities = retrieveAuthoritiesIfNecessary(userFromHeader, storedGrants);
                } else {
                  try {
                    LdapUserDetails userDetails =
                        (LdapUserDetails) loadUserByUsername(userFromHeader);
                    authorities = userDetails.getAuthorities();

                    Set<GrantedAuthority> tempLocalAuthorities =
                        new HashSet<GrantedAuthority>(Arrays.asList(authorities));
                    tempLocalAuthorities.add(AUTHENTICATED_AUTHORITY);
                    authorities = tempLocalAuthorities.toArray(new GrantedAuthority[0]);

                  } catch (UsernameNotFoundException e) {
                    LOGGER.log(
                        Level.WARNING, "User not found in the LDAP directory: " + e.getMessage());

                    Set<GrantedAuthority> tempLocalAuthorities = new HashSet<GrantedAuthority>();
                    tempLocalAuthorities.add(AUTHENTICATED_AUTHORITY);
                    authorities = tempLocalAuthorities.toArray(new GrantedAuthority[0]);
                  }
                }

              } else {
                String groups = r.getHeader(headerGroups);

                List<GrantedAuthority> localAuthorities = new ArrayList<GrantedAuthority>();
                localAuthorities.add(AUTHENTICATED_AUTHORITY);

                if (groups != null) {
                  StringTokenizer tokenizer = new StringTokenizer(groups, headerGroupsDelimiter);
                  while (tokenizer.hasMoreTokens()) {
                    final String token = tokenizer.nextToken().trim();
                    localAuthorities.add(new GrantedAuthorityImpl(token));
                  }
                }

                authorities = localAuthorities.toArray(new GrantedAuthority[0]);

                SearchTemplate searchTemplate = new UserSearchTemplate(userFromHeader);

                Set<String> foundAuthorities =
                    proxyTemplate.searchForSingleAttributeValues(searchTemplate, authorities);
                Set<GrantedAuthority> tempLocalAuthorities = new HashSet<GrantedAuthority>();

                String[] authString = foundAuthorities.toArray(new String[0]);
                for (int i = 0; i < authString.length; i++) {
                  tempLocalAuthorities.add(new GrantedAuthorityImpl(authString[i]));
                }

                authorities = tempLocalAuthorities.toArray(new GrantedAuthority[0]);
                authContext.put(userFromHeader, authorities);

                auth = new UsernamePasswordAuthenticationToken(userFromHeader, "", authorities);
              }
              authContext.put(userFromHeader, authorities);
              auth = new UsernamePasswordAuthenticationToken(userFromHeader, "", authorities);
            }

            retrievedUser = userFromHeader;

            SecurityContextHolder.getContext().setAuthentication(auth);
            chain.doFilter(r, response);
          }

          public void destroy() {}
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
    if (getLDAPURL() == null) {
      proxyTemplate = new ReverseProxySearchTemplate();
      DefaultReverseProxyAuthenticator authenticator =
          new DefaultReverseProxyAuthenticator(retrievedUser, authorities);
      ReverseProxyAuthoritiesPopulatorImpl authoritiesPopulator =
          new ReverseProxyAuthoritiesPopulatorImpl(authContext);
      ProviderManager pm = new ProviderManager();
      List<AuthenticationProvider> providers = new ArrayList<>();
      // talk to Reverse Proxy Authentication
      providers.add(new ReverseProxyAuthenticationProvider(authenticator, authoritiesPopulator));
      // these providers apply everywhere
      RememberMeAuthenticationProvider rmap = new RememberMeAuthenticationProvider();
      rmap.setKey(Jenkins.getInstance().getSecretKey());
      providers.add(rmap);
      // this doesn't mean we allow anonymous access.
      // we just authenticate anonymous users as such,
      // so that later authorization can reject them if so configured
      AnonymousAuthenticationProvider aap = new AnonymousAuthenticationProvider();
      aap.setKey("anonymous");
      providers.add(aap);
      pm.setProviders(providers);
      return new SecurityComponents(pm, new ReverseProxyUserDetailsService(authoritiesPopulator));
    } else {
      DefaultInitialDirContextFactory dirContextFactory =
          new DefaultInitialDirContextFactory(getLDAPURL());
      if (managerDN != null && getManagerPassword() != null) {
        dirContextFactory.setManagerDn(managerDN);
        dirContextFactory.setManagerPassword(fixEmptyAndTrim(getManagerPassword().getPlainText()));
      }
      dirContextFactory.setExtraEnvVars(Collections.singletonMap(Context.REFERRAL, "follow"));
      ldapTemplate = new LdapTemplate(dirContextFactory);
      FilterBasedLdapUserSearch ldapUserSearch =
          new FilterBasedLdapUserSearch(userSearchBase, userSearch, dirContextFactory);
      ldapUserSearch.setSearchSubtree(true);
      BindAuthenticator2 bindAuthenticator = new BindAuthenticator2(dirContextFactory);
      // this is when we need to find it.
      bindAuthenticator.setUserSearch(ldapUserSearch);
      ProxyLDAPAuthoritiesPopulator authoritiesPopulator =
          new ProxyLDAPAuthoritiesPopulator(dirContextFactory, groupSearchBase);
      // see DefaultLdapAuthoritiesPopulator for other possible configurations
      authoritiesPopulator.setSearchSubtree(true);
      authoritiesPopulator.setGroupSearchFilter(
          "(| (member={0}) (uniqueMember={0}) (memberUid={1}))");
      ProviderManager pm = new ProviderManager();
      List<AuthenticationProvider> providers = new ArrayList<>();
      // talk to Reverse Proxy Authentication + Authorisation via LDAP
      LdapAuthenticationProvider authenticationProvider =
          new LdapAuthenticationProvider(bindAuthenticator, authoritiesPopulator);
      providers.add(authenticationProvider);
      RememberMeAuthenticationProvider rmap = new RememberMeAuthenticationProvider();
      rmap.setKey(Jenkins.getInstance().getSecretKey());
      providers.add(rmap);
      AnonymousAuthenticationProvider aap = new AnonymousAuthenticationProvider();
      aap.setKey("anonymous");
      providers.add(aap);
      pm.setProviders(providers);
      if (groupMembershipFilter != null || groupNameAttribute != null) {
        if (groupMembershipFilter != null) {
          authoritiesPopulator.setGroupSearchFilter(groupMembershipFilter);
        }
        if (groupNameAttribute != null) {
          authoritiesPopulator.setGroupRoleAttribute(groupNameAttribute);
        }
      }
      return new SecurityComponents(
          pm, new ProxyLDAPUserDetailsService(ldapUserSearch, authoritiesPopulator));
    }
  }

  /** {@inheritDoc} */
  @Override
  public UserDetails loadUserByUsername(String username)
      throws UsernameNotFoundException, DataAccessException {
    UserDetails userDetails = getSecurityComponents().userDetails.loadUserByUsername(username);
    if (userDetails instanceof LdapUserDetails) {
      updateLdapUserDetails((LdapUserDetails) userDetails);
    }
    return userDetails;
  }

  public LdapUserDetails updateLdapUserDetails(LdapUserDetails d) {
    LOGGER.log(Level.FINEST, "displayNameLdapAttribute" + displayNameLdapAttribute);
    LOGGER.log(Level.FINEST, "disableLdapEmailResolver" + disableLdapEmailResolver);
    LOGGER.log(Level.FINEST, "emailAddressLdapAttribute" + emailAddressLdapAttribute);
    if (d.getAttributes() == null) {
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
            if (existing == null || !existing.hasExplicitlyConfiguredAddress()) {
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
  public GroupDetails loadGroupByGroupname(String groupname)
      throws UsernameNotFoundException, DataAccessException {

    final Set<String> groups;

    if (getLDAPURL() != null) {
      // TODO: obtain a DN instead so that we can obtain multiple attributes later
      String searchBase = groupSearchBase != null ? groupSearchBase : "";
      String searchFilter = groupSearchFilter != null ? groupSearchFilter : GROUP_SEARCH;
      groups =
          ldapTemplate.searchForSingleAttributeValues(
              searchBase, searchFilter, new String[] {groupname}, "cn");
    } else {
      Authentication auth = SecurityContextHolder.getContext().getAuthentication();
      GrantedAuthority[] authorities = authContext != null ? authContext.get(auth.getName()) : null;

      SearchTemplate searchTemplate = new GroupSearchTemplate(groupname);

      groups = proxyTemplate.searchForSingleAttributeValues(searchTemplate, authorities);
    }

    if (groups.isEmpty()) throw new UsernameNotFoundException(groupname);

    return new GroupDetails() {
      @Override
      public String getName() {
        return groups.iterator().next();
      }
    };
  }

  @Extension
  public static class ProxyLDAPDescriptor extends Descriptor<SecurityRealm> {

    @Override
    public String getDisplayName() {
      return Messages.ReverseProxySecurityRealm_DisplayName();
    }

    @POST
    public FormValidation doServerCheck(
        @QueryParameter final String server,
        @QueryParameter final String managerDN,
        @QueryParameter final String managerPassword) {

      final String trimmedServer = fixEmptyAndTrim(server);
      if (trimmedServer == null) {
        return FormValidation.error("Server is null or empty");
      }

      if (!Jenkins.get().hasPermission(Jenkins.ADMINISTER)) {
        return FormValidation.ok();
      }

      try {
        Hashtable<String, String> props = new Hashtable<String, String>();
        if (managerDN != null && managerDN.trim().length() > 0 && !"undefined".equals(managerDN)) {
          props.put(Context.SECURITY_PRINCIPAL, managerDN);
        }
        if (managerPassword != null
            && managerPassword.trim().length() > 0
            && !"undefined".equals(managerPassword)) {
          props.put(Context.SECURITY_CREDENTIALS, managerPassword);
        }

        props.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        props.put(Context.PROVIDER_URL, toProviderUrl(trimmedServer, ""));

        DirContext ctx = new InitialDirContext(props);
        ctx.getAttributes("");
        return FormValidation.ok(); // connected
      } catch (NamingException e) {
        // trouble-shoot
        Matcher m =
            Pattern.compile(
                    "(ldaps?://)?([^:]+)(?:\\:(\\d+))?(\\s+(ldaps?://)?([^:]+)(?:\\:(\\d+))?)*")
                .matcher(trimmedServer.trim());
        if (!m.matches())
          return FormValidation.error(Messages.ReverseProxySecurityRealm_SyntaxOfServerField());

        try {
          InetAddress adrs = InetAddress.getByName(m.group(2));
          int port = m.group(1) != null ? 636 : 389;
          if (m.group(3) != null) port = Integer.parseInt(m.group(3));
          Socket s = new Socket(adrs, port);
          s.close();
        } catch (UnknownHostException x) {
          return FormValidation.error(
              Messages.ReverseProxySecurityRealm_UnknownHost(x.getMessage()));
        } catch (IOException x) {
          return FormValidation.error(
              x, Messages.ReverseProxySecurityRealm_UnableToConnect(trimmedServer, x.getMessage()));
        }

        // otherwise we don't know what caused it, so fall back to the general error report
        // getMessage() alone doesn't offer enough
        return FormValidation.error(
            e, Messages.ReverseProxySecurityRealm_UnableToConnect(trimmedServer, e));
      } catch (NumberFormatException x) {
        // The getLdapCtxInstance method throws this if it fails to parse the port number
        return FormValidation.error(Messages.ReverseProxySecurityRealm_InvalidPortNumber());
      }
    }
  }

  public static class ReverseProxyUserDetailsService implements UserDetailsService {

    private final ReverseProxyAuthoritiesPopulator authoritiesPopulator;

    public ReverseProxyUserDetailsService(ReverseProxyAuthoritiesPopulator authoritiesPopulator) {
      this.authoritiesPopulator = authoritiesPopulator;
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

  private GrantedAuthority[] retrieveAuthoritiesIfNecessary(
      final String userFromHeader, final GrantedAuthority[] storedGrants) {

    GrantedAuthority[] authorities = storedGrants;

    if (getLDAPURL() != null) {

      long current = System.currentTimeMillis();
      if (authorityUpdateCache != null && authorityUpdateCache.containsKey(userFromHeader)) {
        long lastTime = authorityUpdateCache.get(userFromHeader);

        // Time in minutes since last occurrence
        long check = (current - lastTime) / 1000 / 60;
        if (check >= updateInterval) {

          LOGGER.log(
              Level.INFO,
              "The check interval reached the threshold of "
                  + check
                  + "min, will now update the authorities");

          LdapUserDetails userDetails = (LdapUserDetails) loadUserByUsername(userFromHeader);
          authorities = userDetails.getAuthorities();

          Set<GrantedAuthority> tempLocalAuthorities =
              new HashSet<GrantedAuthority>(Arrays.asList(authorities));
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
  private static String addPrefix(String server) {
    if (server.contains("://")) return server;
    else return "ldap://" + server;
  }
}
