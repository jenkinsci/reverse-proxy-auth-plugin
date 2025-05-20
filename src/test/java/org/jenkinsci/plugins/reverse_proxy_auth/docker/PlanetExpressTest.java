package org.jenkinsci.plugins.reverse_proxy_auth.docker;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assume.assumeFalse;
import static org.junit.Assume.assumeTrue;

import hudson.Functions;
import hudson.tasks.MailAddressResolver;
import hudson.util.Secret;
import org.jenkinsci.plugins.reverse_proxy_auth.ReverseProxySecurityRealm;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.RealJenkinsRule;
import org.springframework.security.ldap.userdetails.LdapUserDetails;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.GenericContainer;

/**
 * Tests the plugin when logging in to rroemhild/test-openldap
 */
public class PlanetExpressTest {

    static final String TEST_IMAGE =
            "ghcr.io/rroemhild/docker-test-openldap:v2.4.0@sha256:4d4f8b1bf729cb3038e0269e360ec082d0d9eddcbd7f00743c3728435f4934e4";
    static final String DN = "dc=planetexpress,dc=com";
    static final String MANAGER_DN = "cn=admin,dc=planetexpress,dc=com";
    static final String MANAGER_SECRET = "GoodNewsEveryone";

    @BeforeClass
    public static void requiresDocker() {
        assumeTrue(DockerClientFactory.instance().isDockerAvailable());
    }

    @BeforeClass
    public static void linuxOnly() {
        assumeFalse(
                "Windows CI builders now have Docker installed…but it does not support Linux images",
                Functions.isWindows() && System.getenv("JENKINS_URL") != null);
    }

    @SuppressWarnings("rawtypes")
    @Rule
    public GenericContainer container = new GenericContainer(TEST_IMAGE).withExposedPorts(10389);

    @Rule
    public RealJenkinsRule rr = new RealJenkinsRule();

    @Test
    public void login() throws Throwable {
        String server = container.getHost() + ":" + container.getFirstMappedPort();
        rr.then(new Login(server));
    }

    private static class Login implements RealJenkinsRule.Step {
        private final String server;

        Login(String server) {
            this.server = server;
        }

        @Override
        public void run(JenkinsRule j) throws Throwable {
            ReverseProxySecurityRealm realm = new ReverseProxySecurityRealm(
                    "X-Forwarded-User", // forwardedUser
                    "X-Forwarded-Email", // forwardedEmail
                    "X-Forwarded-DisplayName", // forwardedDisplayName
                    "X-Forwarded-Groups", // headerGroups
                    "|", // headerGroupsDelimiter
                    "", // customLogInUrl
                    "", // customLogOutUrl
                    server, // server
                    DN, // rootDN
                    false, // inhibitInferRootDN
                    "", // userSearchBase
                    "", // userSearch
                    "", // groupSearchBase
                    "", // groupSearchFilter
                    "", // groupMembershipFilter
                    "", // groupNameAttribute
                    MANAGER_DN, // managerDN
                    Secret.fromString(MANAGER_SECRET), // managerPassword
                    15, // updateInterval
                    false, // disableLdapEmailResolver
                    "cn", // displayNameLdapAttribute
                    "mail" // emailAddressLdapAttribute
                    );
            j.jenkins.setSecurityRealm(realm);
            j.configRoundtrip();
            try (JenkinsRule.WebClient wc = j.createWebClient()) {
                wc.addRequestHeader(realm.getForwardedUser(), "fry");
                String content = wc.login("fry", "fry").goTo("whoAmI").getBody().getTextContent();
                assertThat(content, containsString("Philip J. Fry"));
            }

            LdapUserDetails zoidberg =
                    (LdapUserDetails) j.jenkins.getSecurityRealm().loadUserByUsername2("zoidberg");
            assertEquals("cn=John A. Zoidberg,ou=people,dc=planetexpress,dc=com", zoidberg.getDn());

            String leelaEmail = MailAddressResolver.resolve(j.jenkins.getUser("leela"));
            assertEquals("leela@planetexpress.com", leelaEmail);
        }
    }
}
