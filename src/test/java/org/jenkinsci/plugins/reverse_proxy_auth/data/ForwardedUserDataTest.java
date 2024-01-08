import hudson.model.User;
import hudson.tasks.Mailer;

public class ForwardedUserDataTest {
    private ForwardedUserData forwardedUserData;
    private User user;

    @Before
    public void setup() {
        forwardedUserData = ForwardedUserData.new();
        user = User.new();
    }

    @Test
    public void basicForwardedUserData() {
        forwardedUserData.setEmail("max.mustermann@example.com");
        assertEquals(forwardedUserData.getEmail(), "max.mustermann@example.com");

        forwardedUserData.setDisplayName("Max Mustermann");
        assertEquals(forwardedUserData.getDisplayName(), "Max Mustermann");
    }

    @Test
    public void testUpdate() {
        user.setFullName("John Doe");
        forwardedUserData.setDisplayName("Max Mustermann");
        forwardedUserData.setEmail("max.mustermann@example.com");
        forwardedUserData.update(user);

        assertEquals(user.getFullName(), "Max Mustermann");

        Mailer.UserProperty emailProp = user.getProperty(Mailer.UserProperty.class);
        assertEquals(emailProp.getConfiguredAddress(), "max.mustermann@example.com");
    }
}