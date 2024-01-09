package org.jenkinsci.plugins.reverse_proxy_auth.data;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import hudson.model.User;
import hudson.tasks.Mailer;

public class ForwardedUserDataTest {
    private ForwardedUserData forwardedUserData;
    private User user;

    @Before
    public void setup() {
        forwardedUserData = new ForwardedUserData();
        user = User.get("Max Mustermann", false, Collections.emptyMap());
    }

    @Test
    public void basicForwardedUserData() {
        forwardedUserData.setEmail("max.mustermann@example.com");
        Assert.assertEquals(forwardedUserData.getEmail(), "max.mustermann@example.com");

        forwardedUserData.setDisplayName("Max Mustermann");
        Assert.assertEquals(forwardedUserData.getDisplayName(), "Max Mustermann");
    }

    @Test
    public void testUpdate() {
        user.setFullName("John Doe");
        forwardedUserData.setDisplayName("Max Mustermann");
        forwardedUserData.setEmail("max.mustermann@example.com");
        forwardedUserData.update(user);

        Assert.assertEquals(user.getFullName(), "Max Mustermann");

        Mailer.UserProperty emailProp = user.getProperty(Mailer.UserProperty.class);
        Assert.assertEquals(emailProp.getConfiguredAddress(), "max.mustermann@example.com");
    }
}