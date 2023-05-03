package org.jenkinsci.plugins.reverse_proxy_auth;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.concurrent.Callable;

import hudson.security.SecurityRealm;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import org.acegisecurity.Authentication;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.userdetails.UserDetails;
import org.apache.commons.io.IOUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;
import org.jvnet.hudson.test.FlagRule;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.recipes.LocalData;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;

public class ReverseProxySecurityRealmTest {
    @Rule
    public final JenkinsRule jenkinsRule = new JenkinsRule();

    @ClassRule
    public static TestRule noSpaceInTmpDirs = FlagRule.systemProperty("jenkins.test.noSpaceInTmpDirs", "true");

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
                "X-Forwarded-User",         // forwardedUser
                "X-Forwarded-Groups",       // headerGroups
                "|",                        // headerGroupsDelimiter
                "",                         // customLogInUrl
                "",                         // customLogOutUrl
                "",                         // server
                "",                         // rootDN
                false,                      // inhibitInferRootDN
                "",                         // userSearchBase
                "",                         // userSearch
                "",                         // groupSearchBase
                "",                         // groupSearchFilter
                "",                         // groupMembershipFilter
                "",                         // groupNameAttribute
                "",                         // managerDN
                Secret.fromString(""),      // managerPassword
                15,                         // updateInterval
                false,                      // disableLdapEmailResolver
                "",                         // displayNameLdapAttribute
                ""                          // emailAddressLdapAttribute
        );
    }

    @Test
    @LocalData
    public void testPasswordMigration() throws IOException {
        final SecurityRealm securityRealm = jenkinsRule.jenkins.getSecurityRealm();
        assertThat(securityRealm, instanceOf(ReverseProxySecurityRealm.class));
        ReverseProxySecurityRealm reverseProxySecurityRealm = (ReverseProxySecurityRealm) securityRealm;
        assertThat(reverseProxySecurityRealm.getManagerPassword().getPlainText(), is("theManagerPassw0rd"));

        // Ensure migration is complete after saving (don't rely on save-on-startup as in some Jenkins releases)
        Jenkins.get().save();
        final String configXml = IOUtils.toString(new FileReader(new File(Jenkins.get().getRootDir(), "config.xml")));
        assertThat(configXml, containsString("<managerPasswordSecret"));
        assertThat(configXml, not(containsString("<managerPassword ")));
        assertThat(configXml, not(containsString("<managerPassword>")));
    }
}
