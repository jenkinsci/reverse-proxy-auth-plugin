reverse-proxy-auth-plugin
=========================

This extension adds to the existing Reverse Proxy Athentication Plugin the possibility to ready LDAP groups from the HTTP Header and also apply Role-based matrix Authorization.

Having this party implemented fills a gap when the user needs a more sophisticated SSO method, like via certificate or any Authentication Management system.

The default value for the Header User Name field is: X-Forwarded-User
The default value for the Header Groups Name field is: X-Forwarded-Groups
The default delimiter, used to split the groups, is: | (pipe)

When the groups are not being forwarded to Jenkins, the user will be only authenticated (if the user name is in the header). In that case, there will be no Granted Authorities associated with that user.

However, when LDAP groups are forwarded, the grant authorities will be processed and loadGroupsByName methods, which is extended from the SecurityRealm. It is needed in order to have the GlobalMatrixAuthorizationStrategy working properly.
