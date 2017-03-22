Jenkins Reverse Proxy Authentication and Authorisation Plugin

The Reverse Proxy Plugin providers developers the ability to have easy and simple Authentication and Authorisation using SSO techniques. The plugin expects that the user to have Jenkins authenticated agains will be informed via a HHTP header field.

When it comes to Authorisation, the plugin has been extended in order to offer two flavours to developers: HTTP header containing LDAP groups; or LDAP discovery. When one of the mentioned favlours is used, the developer can have Jenkins configured to use Role Based Matrix Authorisation, that will read the groups that were fed to the Reverse Proxy plugin.

The default values for the HTTP header fields are:

1. Header User Name: X-Forwarded-User
2. Header User Mail: X-Forwarded-Mail
3. Header User Display Name: X-Forwarded-DisplayName
4. Header Groups Name: X-Forwarded-Groups
5. Header Groups Delimiter: |
 
The LDAP options can be displayed via the Advanced... button, located on the right side of the security settings.

If no LDAP information is given, the default used will be the HEADER fields. However, if both are configured, the LDAP has priority over the HTTP header.

If the username is not forwaded to Jenkins, the user will be authenticated as ANONYMOUS. When LDAP groups are sent via the HTTP header, there is no check if the username exists in the LDAP directory, so protect your proxy in order to avoid HTTP Header injection. Once an username is informed, the user will be authenticated. If no groups are returned from the LDAP search, the user will still be authenticated, but no other grants will be given.

However, once the LDAP is properly configured instead of groups on the HTTP header, there is guarantee that only the groups of a given user will be returned. There is no possibility to get groups injected via the header.


#Apache httpd configuration example

Here is a simple httpd configuration (apache.conf) made to proxypass 1 to 100 jenkins called ci00 to ci99.
Basic authentication uses an AuthUserFile and many AuthLDAP.
User, display name, mail and groups are injected as headers.
Injected groups are the ldap ones and the local httpd ones (in dbm format).

```
    <Location /ci01>
        AuthBasicProvider auth-file ldap-1 ldap-2
        AuthType Basic
        AuthName "Jenkins"

        Require valid-user
        Order deny,allow
        Allow from all
    </Location>

    <Location /ci02>
        AuthBasicProvider auth-file ldap-1 ldap-2
        AuthType Basic
        AuthName "Jenkins"

        Require valid-user
        Order deny,allow
        Allow from all
    </Location>


    #Redirect jenkins (for headers)
    RewriteRule ^/ci01$ /ci01/ [R]
    RewriteRule ^/ci02$ /ci02/ [R]

    ProxyPass /ci01  http://jenkins-1-real-address/ci01 nocanon
    ProxyPassReverse /ci01 http://jenkins-1-real-address/ci01

    ProxyPass /ci02  http://jenkins-2-real-address/ci02 nocanon
    ProxyPassReverse /ci02 http://jenkins-2-real-address/ci02

    RewriteMap jenkins-groups dbm:/path-to-jenkins-groups.dbm

    #WARNING jenkins is not protected on direct access !
    #Allow any jenkins from ci00 to ci99


     #Keep the location match regex as simple as possible
     #Otherwise we may send some internal js call without authentication.
     <LocationMatch  "^/ci\d\d">

        # jenkins reverse proxy auth configuration
        # prevent the client from setting this header
        RequestHeader unset X-Forwarded-User
        RequestHeader unset X-Forwarded-Groups
        RequestHeader unset X-Forwarded-Mail
        RequestHeader unset X-Forwarded-DisplayName

        RequestHeader set X-Forwarded-Proto "https"
        RequestHeader set X-Forwarded-Port "443"

        # Adds the X-Forwarded-User header that indicates the current user name.
        # this portion came from http://old.nabble.com/Forcing-a-proxied-host-to-generate-REMOTE_USER-td2911573.html#a2914465
        RewriteEngine On
        # see the Apache documentation on why this has to be lookahead
        RewriteCond %{LA-U:REMOTE_USER} (.+)
        # this actually doesn't rewrite anything. what we do here is to set RU to the match above
        # "NS" prevents flooding the error log
        RewriteRule .* - [E=RU:%1,NS]
        RequestHeader set X-Forwarded-User %{RU}e

        #inject mail & display name
        RequestHeader set X-Forwarded-Mail %{AUTHENTICATE_MAIL}e
        RequestHeader set X-Forwarded-DisplayName %{AUTHENTICATE_DISPLAYNAME}e

        #inject groups
        RewriteRule .* - [E=RG:${jenkins-groups:%{REMOTE_USER}}]
        RequestHeader set X-Forwarded-Groups %{RG}e
    </LocationMatch>

```