package org.jenkinsci.plugins.reverse_proxy_auth.service;

import static hudson.Util.fixNull;

import hudson.security.SecurityRealm;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import jenkins.util.SetContextClassLoader;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;

/** {@link LdapAuthoritiesPopulator} that adds the automatic 'authenticated' role. */
public class ProxyLDAPAuthoritiesPopulator extends DefaultLdapAuthoritiesPopulator {

    // Make these available (private in parent class and no get methods!)
    private String rolePrefix = "ROLE_";
    private boolean convertToUpperCase = true;

    public ProxyLDAPAuthoritiesPopulator(ContextSource contextSource, String groupSearchBase) {
        super(contextSource, fixNull(groupSearchBase));

        super.setRolePrefix("");
        super.setConvertToUpperCase(false);
    }

    @Override
    protected Set<GrantedAuthority> getAdditionalRoles(DirContextOperations user, String username) {
        return Collections.singleton(SecurityRealm.AUTHENTICATED_AUTHORITY2);
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
     * <p>We'd like to retain the original name, but we historically used to do "ROLE_GROUPNAME". So
     * to remain backward compatible, we make the super class pass the unmodified "groupName", then do
     * the backward compatible translation here, so that the user gets both "ROLE_GROUPNAME" and
     * "groupName".
     */
    @Override
    @SuppressWarnings("unchecked")
    public Set<GrantedAuthority> getGroupMembershipRoles(String userDn, String username) {
        Set<GrantedAuthority> names;
        try (SetContextClassLoader sccl = new SetContextClassLoader(ProxyLDAPAuthoritiesPopulator.class)) {
            names = super.getGroupMembershipRoles(userDn, username);
        }

        Set<GrantedAuthority> r = new HashSet<GrantedAuthority>(names.size() * 2);
        r.addAll(names);

        for (GrantedAuthority ga : names) {
            String role = ga.getAuthority();

            // backward compatible name mangling
            if (convertToUpperCase) role = role.toUpperCase();
            r.add(new SimpleGrantedAuthority(rolePrefix + role));
        }

        return r;
    }
}
