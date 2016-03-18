Jenkins Reverse Proxy Authentication and Authorisation Plugin

The Reverse proxy plugin providers developers the ability to have easy and simple authentication and authorisation using SSO techniques. The plugin authenticates the user in Jenkins via a HTTP header field.

When it comes to authorisation, the plugin has been extended in order to offer two flavours to developers: HTTP header containing LDAP groups; or LDAP discovery. When one of the mentioned favlours is used, the developer can have Jenkins configured to use role based matrix authorisation, that will read the groups that were fed to the Reverse Proxy plugin.

The default values for the HTTP header fields are:

1. Header User Name: X-Forwarded-User
2. Header Groups Name: X-Forwarded-Groups
3. Header Groups Delimiter: |
 
The LDAP options can be displayed via the Advanced... button, located on the right side of the security settings.

If no LDAP information is given, the default used will be the HEADER fields. However, if both are configured, the LDAP has priority over the HTTP header.

If the username is not forwarded to Jenkins, the user will be authenticated as ANONYMOUS. When LDAP groups are sent via the HTTP header, there is no check if the username exists in the LDAP directory, so protect your proxy in order to avoid HTTP Header injection. Once an username is informed, the user will be authenticated. If no groups are returned from the LDAP search, the user will still be authenticated, but no other grants will be given.

However, once the LDAP is properly configured instead of groups on the HTTP header, there is guarantee that only the groups of a given user will be returned. There is no possibility to get groups injected via the header.
