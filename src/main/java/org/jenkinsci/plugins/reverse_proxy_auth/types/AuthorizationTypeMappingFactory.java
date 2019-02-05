package org.jenkinsci.plugins.reverse_proxy_auth.types;

import hudson.ExtensionPoint;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.security.SecurityRealm;
import jenkins.model.Jenkins;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.ldap.LdapUserDetails;
import org.springframework.web.context.WebApplicationContext;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import static hudson.security.SecurityRealm.AUTHENTICATED_AUTHORITY;

/**
 * Different types of authorization strategies
 */
public abstract class AuthorizationTypeMappingFactory extends AbstractDescribableImpl<AuthorizationTypeMappingFactory> implements ExtensionPoint {

    /**
     * Retrieves the authorities from a given user
     * @param userFromHeader - the user extracted from the HTTP header
     * @param request - the http request
     * @return GrantedAuthority[]
     */
    public abstract GrantedAuthority[] retrieveAuthorities(String userFromHeader, HttpServletRequest request);

    /**
     * Creates the security component for the corresponded authorization strategy
     * @param appContext - application context
     * @return - the security component
     */
    public abstract SecurityRealm.SecurityComponents createUserDetailService(WebApplicationContext appContext);

    /**
     * Path to the groovy file used in the Spring injection of the Security Realm
     * @return - path to the groovy file of the corresponded security realm used
     */
    public abstract String getFilename();

    /**
     * Abstraction of loadGroupByGroupname so each authorization strategy could make its own implmentation
     * @param groupname - group name to lookup
     * @return the groups in the LDAP tree which contains the groupname
     */
    public abstract Set<String> loadGroupByGroupname(String groupname);


    /**
     * Get the Security Realm
     * @return the security realm
     */
    public static SecurityRealm getSecurityRealm() {
        return Jenkins.getActiveInstance().getSecurityRealm();
    }

    /** {@inheritDoc} */
    @Override
    public AuthorizationTypeMappingFactoryDescriptor getDescriptor() {
        return (AuthorizationTypeMappingFactoryDescriptor) super.getDescriptor();
    }

    /**
     * Descriptor for the {@link AuthorizationTypeMappingFactory}
     */
    public static class AuthorizationTypeMappingFactoryDescriptor extends Descriptor<AuthorizationTypeMappingFactory> {
        @Override
        public String getDisplayName() {
            return "AuthorizationTypeMappingFactoryDescriptor";
        }
    }

    /**
     * Retrieves again the authorities in case the time they were in the cache was expired
     * @param authorityUpdateCache -  the frequency which the authorities cache is updated per connected user
     * @param updateInterval - The interval specified in minutes for updating the LDAP authorities
     * @param userFromHeader - The user extracted from the HTTP header
     * @param storedGrants - The granted authorities stored in the cache
     * @return the GrantedAuthorities for a given user
     */
    protected GrantedAuthority[] retrieveAuthoritiesIfNecessary(Hashtable<String, Long> authorityUpdateCache, int updateInterval, final String userFromHeader, final GrantedAuthority[] storedGrants) {
        GrantedAuthority[] authorities = storedGrants;
        long current = System.currentTimeMillis();

        if (authorityUpdateCache != null && authorityUpdateCache.containsKey(userFromHeader)) {
            long lastTime = authorityUpdateCache.get(userFromHeader);

            //Time in minutes since last occurrence
            long check = (current - lastTime) / 1000 / 60;
            if (check >= updateInterval) {

                LOGGER.log(Level.INFO, "The check interval reached the threshold of " + check + "min, will now update the authorities");

                LdapUserDetails userDetails = (LdapUserDetails) getSecurityRealm().loadUserByUsername(userFromHeader);
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

        return authorities;
    }

    private static final Logger LOGGER = Logger.getLogger(AuthorizationTypeMappingFactory.class.getName());
}
