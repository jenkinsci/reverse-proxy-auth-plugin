package org.jenkinsci.plugins.reverse_proxy_auth.service;

import hudson.security.UserMayOrMayNotExistException2;
import java.util.Collection;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttributes;
import jenkins.util.SetContextClassLoader;
import org.apache.commons.collections.map.LRUMap;
import org.springframework.dao.DataAccessException;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.ldap.search.LdapUserSearch;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapUserDetailsImpl;

public class ProxyLDAPUserDetailsService implements UserDetailsService {

    private static final Logger LOGGER = Logger.getLogger(ProxyLDAPUserDetailsService.class.getName());
    private static final int RETRY_TIMES = 3;
    private static final long MAX_WAIT_INTERVAL = 5000L; // 5 seconds

    public final LdapUserSearch ldapSearch;
    public final LdapAuthoritiesPopulator authoritiesPopulator;

    /**
     * {@link BasicAttributes} in LDAP tend to be bulky (about 20K at size), so interning them to keep
     * the size under control. When a programmatic client is not smart enough to reuse a session, this
     * helps keeping the memory consumption low.
     */
    private final LRUMap attributesCache = new LRUMap(32);

    public ProxyLDAPUserDetailsService(LdapUserSearch ldapSearch, LdapAuthoritiesPopulator authoritiesPopulator) {
        this.ldapSearch = ldapSearch;
        this.authoritiesPopulator = authoritiesPopulator;
    }

    /**
     * Loads the user by username
     *
     * @param username the username
     * @return user
     * @throws UsernameNotFoundException if user not found
     * @throws DataAccessException on data access exception
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        int retries = 0;
        while (retries < RETRY_TIMES) {
            try (SetContextClassLoader sccl = new SetContextClassLoader(ProxyLDAPUserDetailsService.class)) {
                DirContextOperations ldapUser = ldapSearch.searchForUser(username);
                // LdapUserSearch does not populate granted authorities (group search).
                // Add those, as done in LdapAuthenticationProvider.createUserDetails().
                LdapUserDetailsImpl.Essence user = new LdapUserDetailsImpl.Essence(ldapUser);
                user.setUsername(username);
                user.setDn(ldapUser.getNameInNamespace()); // otherwise the DN is missing the DC

                // intern attributes
                Attributes v = ldapUser.getAttributes();
                synchronized (attributesCache) {
                    Attributes vv = (Attributes) attributesCache.get(v);
                    if (vv == null) {
                        attributesCache.put(v, v);
                    } else {
                        v = vv;
                    }
                }

                Collection<? extends GrantedAuthority> extraAuthorities =
                        authoritiesPopulator.getGrantedAuthorities(ldapUser, username);
                for (GrantedAuthority extraAuthority : extraAuthorities) {
                    user.addAuthority(extraAuthority);
                }
                return user.createUserDetails();
            } catch (AuthenticationServiceException ldapEx) {
                long waitTime = Math.min(getWaitTimeExp(retries), MAX_WAIT_INTERVAL);
                String msg = String.format(
                        "Failed to search LDAP for username %s, will retry after waiting for %d" + " milliseconds",
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
        throw new UserMayOrMayNotExistException2("Failed to search LDAP for user after all the retries.");
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
