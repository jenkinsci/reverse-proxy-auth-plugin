Jenkins Reverse Proxy Authentication and Authorisation Plugin

The Reverse Proxy Plugin providers developers the ability to have easy and simple Authentication and Authorisation using SSO techniques. The plugin expects that the user to have Jenkins authenticated agains will be informed via a HHTP header field.

When it comes to Authorisation, the plugin has been extended in order to offer two flavours to developers: HTTP header containing LDAP groups; or LDAP discovery. When one of the mentioned favlours is used, the developer can have Jenkins configured to use Role Based Matrix Authorisation, that will read the groups that were fed to the Reverse Proxy plugin.

The default values for the HTTP header fields are:

1. Header User Name: X-Forwarded-User
2. Header Groups Name: X-Forwarded-Groups
3. Header Groups Delimiter: |
 
The LDAP options can be displayed via the Advanced... button, located on the right side of the security settings.

If no LDAP information is given, the default used will be the HEADER fields. However, if both are configured, the LDAP has priority over the HTTP header.

If the username is not forwaded to Jenkins, the user will be authenticated as ANONYMOUS. There is no check if the username exists in the LDAP directory, so protect your proxy in order to avoid HTTP Header injection. Once an username is informed, the user will be authenticated. If no groups are returned from the LDAP search, the user will still be authenticated, but no other grants will be given.
