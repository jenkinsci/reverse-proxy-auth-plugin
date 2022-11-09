package org.jenkinsci.plugins.reverse_proxy_auth;

import java.util.concurrent.Callable;

import org.acegisecurity.Authentication;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.userdetails.UserDetails;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;

import hudson.security.SecurityRealm;
import jenkins.model.Jenkins;

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
        return new ReverseProxySecurityRealm(
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
                5000,                 // ldapConnectTimeout
                60000,                // ldapReadTimeout
                false,                // disableLdapEmailResolver
                "",                   // displayNameLdapAttribute
                ""                    // emailAddressLdapAttribute
        );
    }
}
