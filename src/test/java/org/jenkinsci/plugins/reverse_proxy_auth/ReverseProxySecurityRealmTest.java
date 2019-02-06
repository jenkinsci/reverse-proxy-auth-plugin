package org.jenkinsci.plugins.reverse_proxy_auth;

import hudson.security.SecurityRealm;
import jenkins.model.Jenkins;
import org.acegisecurity.Authentication;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.userdetails.UserDetails;
import org.jenkinsci.plugins.reverse_proxy_auth.types.GroupsAuthorizationType;
import org.jenkinsci.plugins.reverse_proxy_auth.types.LdapAuthorizationType;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.recipes.LocalData;

import static org.hamcrest.Matchers.isEmptyOrNullString;
import static org.junit.Assert.assertThat;
import static org.hamcrest.Matchers.is;

import java.util.concurrent.Callable;

public class ReverseProxySecurityRealmTest {
    @Rule
    public final JenkinsRule jenkinsRule = new JenkinsRule();

    private Jenkins jenkins;

    @Before
    public void setUp() {
        jenkins = jenkinsRule.jenkins;
    }

    @Test
    public void basicGetUserDetails() {
        final ReverseProxySecurityRealm realm = createBasicRealm();
        final UserDetails userDetails = realm.loadUserByUsername("test@example.com");
        Assert.assertEquals("test@example.com", userDetails.getUsername());
    }

    @Test
    @Issue("JENKINS-49274")
    public void basicAuthenticate() throws Exception {
        final ReverseProxySecurityRealm realm = createBasicRealm();
        jenkins.setSecurityRealm(realm);

        final JenkinsRule.WebClient client = jenkinsRule.createWebClient();
        client.addRequestHeader(realm.getForwardedUser(), "test@example.com");
        final Authentication authentication = client.executeOnServer(new Callable<Authentication>() {
            @Override
            public Authentication call() {
                return Jenkins.getAuthentication();
            }
        });
        Assert.assertEquals("Authentication should match",
                new UsernamePasswordAuthenticationToken(
                        "test@example.com",
                        "",
                        new GrantedAuthority[] { SecurityRealm.AUTHENTICATED_AUTHORITY }),
                authentication);
    }

    private ReverseProxySecurityRealm createBasicRealm() {
        GroupsAuthorizationType groupsAuthorizationType = new GroupsAuthorizationType("X-Forwarded-Groups", "|");
        ReverseProxySecurityRealm reverseProxySecurityRealm = new ReverseProxySecurityRealm(
                "X-Forwarded-User",   // forwardedUser
                "X-Forwarded-Groups", // headerGroups
                "|",                  // headerGroupsDelimiter
                "",                   // customLogInUrl
                "",                   // customLogOutUrl
                "",                   // server
                "",                   // rootDN
                false,                // inhibitInferRootDN
                "",                   // userSearchBase
                "",                   // userSearch
                "",                   // groupSearchBase
                "",                   // groupSearchFilter
                "",                   // groupMembershipFilter
                "",                   // groupNameAttribute
                "",                   // managerDN
                "",                   // managerPassword
                15,                   // updateInterval
                false,                // disableLdapEmailResolver
                "",                   // displayNameLdapAttribute
                "",                    // emailAddressLdapAttribute
                groupsAuthorizationType
        );
        return reverseProxySecurityRealm;
    }

    @LocalData
    @Test
    public void readResolveLdap() {
        ReverseProxySecurityRealm reverseProxySecurityRealm = (ReverseProxySecurityRealm) jenkins.getSecurityRealm();
        LdapAuthorizationType ldapAuthorizationType = (LdapAuthorizationType) reverseProxySecurityRealm.getAuthorizationTypeMappingFactory();
        assertThat(ldapAuthorizationType.server, is("ldap://127.0.0.1:3890"));
        assertThat(ldapAuthorizationType.rootDN, is("dc=corporation,dc=net"));
        assertThat(ldapAuthorizationType.inhibitInferRootDN, is(false));
        assertThat(ldapAuthorizationType.userSearchBase, is("ou=employees,ou=people"));
        assertThat(ldapAuthorizationType.userSearch, is("uid={0}"));
        assertThat(ldapAuthorizationType.groupSearchBase, is("ou=groups"));
        assertThat(ldapAuthorizationType.groupSearchFilter, is("(uniqueMember={0})"));
        assertThat(ldapAuthorizationType.managerDN, is("cn=admin,dc=corporation,dc=net"));
        assertThat(ldapAuthorizationType.disableLdapEmailResolver, is(false));
        assertThat(ldapAuthorizationType.displayNameLdapAttribute, isEmptyOrNullString());
        assertThat(ldapAuthorizationType.emailAddressLdapAttribute, isEmptyOrNullString());
    }

    @LocalData
    @Test
    public void readResolveGroups() {
        ReverseProxySecurityRealm reverseProxySecurityRealm = (ReverseProxySecurityRealm) jenkins.getSecurityRealm();
        GroupsAuthorizationType groupsAuthorizationType = (GroupsAuthorizationType) reverseProxySecurityRealm.getAuthorizationTypeMappingFactory();
        assertThat(groupsAuthorizationType.headerGroups, is("X-Forwarded-Groups"));
        assertThat(groupsAuthorizationType.headerGroupsDelimiter, is("|"));

    }
}
