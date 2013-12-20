reverse-proxy-auth-plugin
=========================

This extension adds to the existing Reverse Proxy Athentication Plugin the possibility to ready LDAP groups via discovery based on username and also apply Role-based matrix Authorization.

Having this party implemented fills a gap when the user needs a more sophisticated SSO method, like via certificate or any Authentication Management system.

The default value for the Header User Name field is: X-Forwarded-User

The LDAP options are activated via the Advanced button.

If the username is not forwaded to Jenkins, the user will be authenticated as ANONYMOUS. There is no check if the username exists in the LDAP directory, so protect your proxy in order to avoid HTTP Header injectio. Once an username is informed, the user will be authenticated. If no groups are returned from the LDAP search, the user will still be authenticated, but no other grants will be given.

This new feature is still work in progress since we also want to make sure that all check are made whn the LDAP settings are not informed. Moreover, there could be also nice to have LDAP groups on the header. It would give a bit more of freedom to the whole SSO mechanism.
