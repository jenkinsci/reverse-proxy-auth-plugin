package org.jenkinsci.plugins.reverse_proxy_auth.data;

import static org.junit.jupiter.api.Assertions.assertEquals;

import hudson.model.User;
import hudson.tasks.Mailer;
import jenkins.model.Jenkins;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.MockAuthorizationStrategy;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
class ForwardedUserDataTest {

    private ForwardedUserData forwardedUserData;
    private User user;

    private JenkinsRule j;

    @BeforeEach
    void setUp(JenkinsRule rule) {
        j = rule;
        j.jenkins.setAuthorizationStrategy(
                new MockAuthorizationStrategy().grant(Jenkins.READ).everywhere().to("Max Mustermann"));

        forwardedUserData = new ForwardedUserData();
        user = User.getOrCreateByIdOrFullName("Max Mustermann");
    }

    @Test
    void basicForwardedUserData() {
        forwardedUserData.setEmail("max.mustermann@example.com");
        assertEquals("max.mustermann@example.com", forwardedUserData.getEmail());

        forwardedUserData.setDisplayName("Max Mustermann");
        assertEquals("Max Mustermann", forwardedUserData.getDisplayName());
    }

    @Test
    void testUpdate() {
        user.setFullName("John Doe");
        forwardedUserData.setDisplayName("Max Mustermann");
        forwardedUserData.update(user);
        assertEquals("Max Mustermann", user.getFullName());

        forwardedUserData.setEmail("max.mustermann@example.com");
        forwardedUserData.update(user);
        Mailer.UserProperty emailProp = user.getProperty(Mailer.UserProperty.class);
        assertEquals("max.mustermann@example.com", emailProp.getAddress());
    }
}
