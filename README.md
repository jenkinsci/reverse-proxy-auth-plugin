reverse-proxy-auth-plugin
=========================

This extension adds to the existing Reverse Proxy Athentication Plugin the possibility to ready LDAP groups from the HTTP Header and also apply Role-based matrix Authorization.

Having this party implemented fills a gat when the user needs a more sophisticated SSO methods, like via certificate or any Authentication Management system.

The default value for the Header User Name field is: X-Forwarded-User
The default value for the Header Groups Name field is: X-forwarded-Groups
The default delimiter, used to split the groups, is: | (pipe)

When the groups are not being forwarded to Jenkins, the user will be only authenticated (if the user name is in the header). In that case, there will be no Granted Authorities associated with that user.
