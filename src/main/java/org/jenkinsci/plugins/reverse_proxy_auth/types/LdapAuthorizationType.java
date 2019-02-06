package org.jenkinsci.plugins.reverse_proxy_auth.types;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.Extension;
import hudson.security.LDAPSecurityRealm;
import hudson.security.SecurityRealm;
import hudson.util.FormValidation;
import hudson.util.Scrambler;
import jenkins.model.Jenkins;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.ldap.InitialDirContextFactory;
import org.acegisecurity.ldap.LdapTemplate;
import org.acegisecurity.ldap.search.FilterBasedLdapUserSearch;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.acegisecurity.userdetails.ldap.LdapUserDetails;
import org.jenkinsci.plugins.reverse_proxy_auth.ReverseProxySecurityRealm;
import org.jenkinsci.plugins.reverse_proxy_auth.service.ProxyLDAPAuthoritiesPopulator;
import org.jenkinsci.plugins.reverse_proxy_auth.service.ProxyLDAPUserDetailsService;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.springframework.web.context.WebApplicationContext;

import javax.annotation.CheckForNull;
import javax.annotation.Nullable;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static hudson.Util.fixEmpty;
import static hudson.Util.fixEmptyAndTrim;
import static hudson.Util.fixNull;
import static hudson.security.SecurityRealm.AUTHENTICATED_AUTHORITY;
import static hudson.security.SecurityRealm.findBean;

/**
 * Represents the LDAP authorization strategy
 */
public class LdapAuthorizationType extends AuthorizationTypeMappingFactory {

    /**
     * Interval to check user authorities via LDAP.
     */
    private static final int CHECK_INTERVAL = 15;

    /**
     * LDAP filter to look for groups by their names.
     *
     * "{0}" is the group name as given by the user.
     * See http://msdn.microsoft.com/en-us/library/aa746475(VS.85).aspx for the syntax by example.
     * WANTED: The specification of the syntax.
     */
    @SuppressFBWarnings(value = "MS_SHOULD_BE_FINAL", justification = "May be used in system groovy scripts")
    public static String GROUP_SEARCH = System.getProperty(LDAPSecurityRealm.class.getName()+".groupSearch",
            "(& (cn={0}) (| (objectclass=groupOfNames) (objectclass=groupOfUniqueNames) (objectclass=posixGroup)))");

    /**
     * LDAP server name(s) separated by spaces, optionally with TCP port number, like "ldap.acme.org"
     * or "ldap.acme.org:389" and/or with protcol, like "ldap://ldap.acme.org".
     */
    public String server;

    /**
     * The root DN to connect to. Normally something like "dc=sun,dc=com"
     *
     * How do I infer this?
     */
    public String rootDN;

    /**
     * Allow the rootDN to be inferred? Default is false.
     * If true, allow rootDN to be blank.
     */
    public boolean inhibitInferRootDN;

    /**
     * Specifies the relative DN from {@link #rootDN the root DN}.
     * This is used to narrow down the search space when doing user search.
     *
     * Something like "ou=people" but can be empty.
     */
    public String userSearchBase;

    /**
     * Query to locate an entry that identifies the user, given the user name string.
     *
     * Normally "uid={0}"
     *
     * @see FilterBasedLdapUserSearch
     */
    public String userSearch;

    /**
     * This defines the organizational unit that contains groups.
     *
     * Normally "" to indicate the full LDAP search, but can be often narrowed down to
     * something like "ou=groups"
     *
     * @see FilterBasedLdapUserSearch
     */
    public String groupSearchBase;

    /**
     * Query to locate an entry that identifies the group, given the group name string. If non-null it will override
     * the default specified by {@link #GROUP_SEARCH}
     *
     * @since 1.5
     */
    public String groupSearchFilter;

    /**
     * Query to locate the group entries that a user belongs to, given the user object. <code>{0}</code>
     * is the user's full DN while {1} is the username.
     */
    public String groupMembershipFilter;

    /**
     * Attribute that should be used instead of CN as name to match a users group name to the groupSearchFilter name.
     * When {@link #groupSearchFilter} is set to search for a field other than CN e.g. <code>GroupDisplayName={0}</code>
     * here you can configure that this (<code>GroupDisplayName</code>) or another field should be used when looking for a users groups.
     */
    public String groupNameAttribute;

    /**
     * If non-null, we use this and {@link #managerPassword}
     * when binding to LDAP.
     *
     * This is necessary when LDAP doesn't support anonymous access.
     */
    public String managerDN;

    /**
     * Scrambled password, used to first bind to LDAP.
     */
    public String managerPassword;

    /**
     * The LDAP display name attribute
     */
    public String displayNameLdapAttribute;

    /**
     * The LDAP email address attribute
     */
    public String emailAddressLdapAttribute;

    /**
     * Disable the LDAP email resolver
     */
    public boolean disableLdapEmailResolver;

    /**
     * Sets an interval for updating the LDAP authorities. The interval is specified in minutes.
     */
    public int updateInterval;

    /**
     * Path to the groovy files which contains the injection of this authorization strategy
     */
    private static final String FILE_NAME = "types/LdapAuthorizationType/ReverseProxyLDAPSecurityRealm.groovy";

    /**
     * Keeps the frequency which the authorities cache is updated per connected user.
     * The types String and Long are used for username and last time checked (in minutes) respectively.
     */
    private transient Hashtable<String, Long> authorityUpdateCache = new Hashtable<>();

    /**
     * Ldap template to connect with LDAP
     */
    private transient LdapTemplate ldapTemplate;

    /**
     * Gets the LDAP URL
     * @return
     */
    public String getLDAPURL() {
        return toProviderUrl(getServerUrl(), fixNull(rootDN));
    }

    /**
     * Keeps the state of connected users and their granted authorities.
     */
    private Hashtable<String, GrantedAuthority[]> authContext = new Hashtable<>();

    /**
     * The authorities that are granted to the authenticated user.
     * It is not necessary, that the authorities will be stored in the config.xml, they blow up the config.xml
     */
    private transient GrantedAuthority[] authorities  = new GrantedAuthority[0];

    @DataBoundConstructor
    public LdapAuthorizationType(String server, String rootDN, boolean inhibitInferRootDN,
                                 String userSearchBase, String userSearch, String groupSearchBase, String groupSearchFilter, String groupMembershipFilter, String groupNameAttribute, String managerDN, String managerPassword,
                                 String displayNameLdapAttribute, String emailAddressLdapAttribute, boolean disableLdapEmailResolver, Integer updateInterval) {

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
        this.disableLdapEmailResolver = disableLdapEmailResolver;
        this.displayNameLdapAttribute = displayNameLdapAttribute;
        this.emailAddressLdapAttribute = emailAddressLdapAttribute;
        this.updateInterval = (updateInterval == null || updateInterval <= 0) ? CHECK_INTERVAL : updateInterval;
    }

    /**
     * Infer the root DN.
     *
     * @return null if not found.
     */
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

    public String getManagerPassword() {
        return Scrambler.descramble(managerPassword);
    }

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

    /**
     * If the given "server name" is just a host name (plus optional host name), add ldap:// prefix.
     * Otherwise assume it already contains the scheme, and leave it intact.
     */
    private static String addPrefix(String server) {
        if(server.contains("://"))  return server;
        else    return "ldap://"+server;
    }

    public GrantedAuthority[] retrieveAuthorities(String userFromHeader, HttpServletRequest r) {
        if (authContext == null) {
            authContext = new Hashtable<>();
        }

        GrantedAuthority []  storedGrants = authContext.get(userFromHeader);

        if (storedGrants != null && storedGrants.length > 1) {
            authorities = retrieveAuthoritiesIfNecessary(authorityUpdateCache, updateInterval, userFromHeader, storedGrants);
        } else {
            try {
                LdapUserDetails userDetails = (LdapUserDetails) getSecurityRealm().loadUserByUsername(userFromHeader);
                authorities = userDetails.getAuthorities();

                Set<GrantedAuthority> tempLocalAuthorities = new HashSet<GrantedAuthority>(Arrays.asList(authorities));
                tempLocalAuthorities.add(AUTHENTICATED_AUTHORITY);
                authorities = tempLocalAuthorities.toArray(new GrantedAuthority[0]);

            } catch (UsernameNotFoundException e) {
                LOGGER.log(Level.WARNING, "User not found in the LDAP directory: " + e.getMessage());

                Set<GrantedAuthority> tempLocalAuthorities = new HashSet<GrantedAuthority>();
                tempLocalAuthorities.add(AUTHENTICATED_AUTHORITY);
                authorities = tempLocalAuthorities.toArray(new GrantedAuthority[0]);
            }
        }
        authContext.put(userFromHeader, authorities);
        return Collections.unmodifiableList(Arrays.asList(authorities)).toArray(new GrantedAuthority[authorities.length]);
    }


    public SecurityRealm.SecurityComponents createUserDetailService(WebApplicationContext appContext) {
        ldapTemplate = new LdapTemplate(findBean(InitialDirContextFactory.class, appContext));

        if (groupMembershipFilter != null || groupNameAttribute != null) {
            ProxyLDAPAuthoritiesPopulator authoritiesPopulator = findBean(ProxyLDAPAuthoritiesPopulator.class, appContext);
            if (groupMembershipFilter != null) {
                authoritiesPopulator.setGroupSearchFilter(groupMembershipFilter);
            }
            if (groupNameAttribute != null) {
                authoritiesPopulator.setGroupRoleAttribute(groupNameAttribute);
            }
        }

        return new SecurityRealm.SecurityComponents(findBean(AuthenticationManager.class, appContext), new ProxyLDAPUserDetailsService(this, (ReverseProxySecurityRealm) getSecurityRealm(), appContext));
    }

    @Override
    public String getFilename() {
        return FILE_NAME;
    }

    @Override
    public Set<String> loadGroupByGroupname(String groupname) {
        // TODO: obtain a DN instead so that we can obtain multiple attributes later
        String searchBase = groupSearchBase != null ? groupSearchBase : "";
        String searchFilter = groupSearchFilter != null ? groupSearchFilter : GROUP_SEARCH;
        return ldapTemplate.searchForSingleAttributeValues(searchBase, searchFilter, new String[]{groupname}, "cn");
    }

    @Extension
    public static class DescriptorImpl extends AuthorizationTypeMappingFactoryDescriptor {
        public String getDisplayName() {
            return "LDAP";
        }

        public FormValidation doServerCheck(
                @QueryParameter final String server,
                @QueryParameter final String managerDN,
                @QueryParameter final String managerPassword) {

            final String trimmedServer = fixEmptyAndTrim(server);
            if (trimmedServer == null) {
                return FormValidation.error("Server is null or empty");
            }

            if (!Jenkins.getActiveInstance().hasPermission(Jenkins.ADMINISTER)) {
                return FormValidation.ok();
            }

            try {
                Hashtable<String,String> props = new Hashtable<String,String>();
                if (managerDN != null && managerDN.trim().length() > 0 && !"undefined".equals(managerDN)) {
                    props.put(Context.SECURITY_PRINCIPAL, managerDN);
                }
                if (managerPassword!=null && managerPassword.trim().length() > 0 && !"undefined".equals(managerPassword)) {
                    props.put(Context.SECURITY_CREDENTIALS, managerPassword);
                }

                props.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
                props.put(Context.PROVIDER_URL, toProviderUrl(trimmedServer, ""));

                DirContext ctx = new InitialDirContext(props);
                ctx.getAttributes("");
                return FormValidation.ok();   // connected
            } catch (NamingException e) {
                // trouble-shoot
                Matcher m = Pattern.compile("(ldaps?://)?([^:]+)(?:\\:(\\d+))?(\\s+(ldaps?://)?([^:]+)(?:\\:(\\d+))?)*").matcher(trimmedServer.trim());
                if(!m.matches())
                    return FormValidation.error(hudson.security.Messages.LDAPSecurityRealm_SyntaxOfServerField());

                try {
                    InetAddress adrs = InetAddress.getByName(m.group(2));
                    int port = m.group(1) != null ? 636 : 389;
                    if(m.group(3) != null)
                        port = Integer.parseInt(m.group(3));
                    Socket s = new Socket(adrs,port);
                    s.close();
                } catch (UnknownHostException x) {
                    return FormValidation.error(hudson.security.Messages.LDAPSecurityRealm_UnknownHost(x.getMessage()));
                } catch (IOException x) {
                    return FormValidation.error(x,hudson.security.Messages.LDAPSecurityRealm_UnableToConnect(trimmedServer, x.getMessage()));
                }

                // otherwise we don't know what caused it, so fall back to the general error report
                // getMessage() alone doesn't offer enough
                return FormValidation.error(e,hudson.security.Messages.LDAPSecurityRealm_UnableToConnect(trimmedServer, e));
            } catch (NumberFormatException x) {
                // The getLdapCtxInstance method throws this if it fails to parse the port number
                return FormValidation.error(hudson.security.Messages.LDAPSecurityRealm_InvalidPortNumber());
            }
        }
    }

    private static final Logger LOGGER = Logger.getLogger(LdapAuthorizationType.class.getName());

}
