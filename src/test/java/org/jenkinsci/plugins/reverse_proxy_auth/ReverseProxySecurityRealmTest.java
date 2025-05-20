package org.jenkinsci.plugins.reverse_proxy_auth;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;

import hudson.security.SecurityRealm;
import hudson.util.Secret;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.Collections;
import jenkins.model.Jenkins;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.jvnet.hudson.test.recipes.LocalData;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;

@WithJenkins
class ReverseProxySecurityRealmTest {

    private JenkinsRule j;

    @BeforeEach
    void setUp(JenkinsRule rule) {
        j = rule;
    }

    @Test
    void basicGetUserDetails() {
        final ReverseProxySecurityRealm realm = createBasicRealm();
        final UserDetails userDetails = realm.loadUserByUsername2("test@example.com");
        assertEquals("test@example.com", userDetails.getUsername());
    }

    @Test
    @Issue("JENKINS-49274")
    void basicAuthenticate() throws Exception {
        final ReverseProxySecurityRealm realm = createBasicRealm();
        j.jenkins.setSecurityRealm(realm);

        try (JenkinsRule.WebClient client = j.createWebClient()) {
            client.addRequestHeader(realm.getForwardedUser(), "test@example.com");
            final Authentication authentication = client.executeOnServer(Jenkins::getAuthentication2);
            assertEquals(
                    new UsernamePasswordAuthenticationToken(
                            "test@example.com", "", Collections.singleton(SecurityRealm.AUTHENTICATED_AUTHORITY2)),
                    authentication,
                    "Authentication should match");
        }
    }

    private ReverseProxySecurityRealm createBasicRealm() {
        return new ReverseProxySecurityRealm(
                "X-Forwarded-User", // forwardedUser
                "X-Forwarded-Email", // forwardedEmail
                "X-Forwarded-DisplayName", // forwardedDisplayName
                "X-Forwarded-Groups", // headerGroups
                "|", // headerGroupsDelimiter
                "", // customLogInUrl
                "", // customLogOutUrl
                "", // server
                "", // rootDN
                false, // inhibitInferRootDN
                "", // userSearchBase
                "", // userSearch
                "", // groupSearchBase
                "", // groupSearchFilter
                "", // groupMembershipFilter
                "", // groupNameAttribute
                "", // managerDN
                Secret.fromString(""), // managerPassword
                15, // updateInterval
                false, // disableLdapEmailResolver
                "", // displayNameLdapAttribute
                "" // emailAddressLdapAttribute
                );
    }

    @Test
    @LocalData
    void testPasswordMigration() throws IOException {
        final SecurityRealm securityRealm = j.jenkins.getSecurityRealm();
        assertThat(securityRealm, instanceOf(ReverseProxySecurityRealm.class));
        ReverseProxySecurityRealm reverseProxySecurityRealm = (ReverseProxySecurityRealm) securityRealm;
        assertThat(reverseProxySecurityRealm.getManagerPassword().getPlainText(), is("theManagerPassw0rd"));

        // Ensure migration is complete after saving (don't rely on save-on-startup as in some Jenkins
        // releases)
        Jenkins.get().save();
        final String configXml =
                IOUtils.toString(new FileReader(new File(Jenkins.get().getRootDir(), "config.xml")));
        assertThat(configXml, containsString("<managerPasswordSecret"));
        assertThat(configXml, not(containsString("<managerPassword ")));
        assertThat(configXml, not(containsString("<managerPassword>")));
    }
}
