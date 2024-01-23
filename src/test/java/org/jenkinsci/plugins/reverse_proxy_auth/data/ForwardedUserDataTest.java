package org.jenkinsci.plugins.reverse_proxy_auth.data;

import hudson.model.User;
import hudson.tasks.Mailer;
import jenkins.model.Jenkins;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.MockAuthorizationStrategy;

public class ForwardedUserDataTest {
    private ForwardedUserData forwardedUserData;
    private User user;

    @Rule
    public JenkinsRule j = new JenkinsRule();

    @Before
    public void setup() {
        j.jenkins.setAuthorizationStrategy(
                new MockAuthorizationStrategy().grant(Jenkins.READ).everywhere().to("Max Mustermann"));

        forwardedUserData = new ForwardedUserData();
        user = User.getOrCreateByIdOrFullName("Max Mustermann");
    }

    @Test
    public void basicForwardedUserData() {
        forwardedUserData.setEmail("max.mustermann@example.com");
        Assert.assertEquals("max.mustermann@example.com", forwardedUserData.getEmail());

        forwardedUserData.setDisplayName("Max Mustermann");
        Assert.assertEquals("Max Mustermann", forwardedUserData.getDisplayName());
    }

    @Test
    public void testUpdate() {
        user.setFullName("John Doe");
        forwardedUserData.setDisplayName("Max Mustermann");
        forwardedUserData.update(user);
        Assert.assertEquals("Max Mustermann", user.getFullName());

        forwardedUserData.setEmail("max.mustermann@example.com");
        forwardedUserData.update(user);
        Mailer.UserProperty emailProp = user.getProperty(Mailer.UserProperty.class);
        Assert.assertEquals("max.mustermann@example.com", emailProp.getAddress());
    }
}
