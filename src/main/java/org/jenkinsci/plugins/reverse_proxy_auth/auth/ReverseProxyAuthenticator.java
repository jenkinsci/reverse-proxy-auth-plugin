package org.jenkinsci.plugins.reverse_proxy_auth.auth;

import org.jenkinsci.plugins.reverse_proxy_auth.ReverseProxySecurityRealm.ReverseProxyUserDetails;

/**
 * @author Wilder Rodrigues (wrodrigues@schubergphilis.com)
 */
public interface ReverseProxyAuthenticator {

	/**
     * Authenticates as a user and obtains additional user information from the directory.
     *
     * @param username the user's login name (<em>not</em> their DN).
     * @param password the user's password supplied at login.
     *
     * @return the details of the successfully authenticated user.
     */
    ReverseProxyUserDetails authenticate(String username, String password);
}