package org.jenkinsci.plugins.reverse_proxy_auth.auth;

/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

import java.util.HashSet;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Set;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jenkinsci.plugins.reverse_proxy_auth.ReverseProxySearchTemplate;
import org.jenkinsci.plugins.reverse_proxy_auth.ReverseProxySecurityRealm.ReverseProxyUserDetails;
import org.jenkinsci.plugins.reverse_proxy_auth.data.SearchTemplate;
import org.jenkinsci.plugins.reverse_proxy_auth.data.UserSearchTemplate;
import org.springframework.util.Assert;


/**
* @author Wilder rodrigues (wrodrigues@schuberphilis.com)
*/
public class DefaultReverseProxyAuthoritiesPopulator implements ReverseProxyAuthoritiesPopulator {

	private static final Log logger = LogFactory.getLog(DefaultReverseProxyAuthoritiesPopulator.class);

   /**
    * A default role which will be assigned to all authenticated users if set
    */
   private GrantedAuthority defaultRole;

   /**
    * An initial context factory is only required if searching for groups is required.
    */
   private ReverseProxySearchTemplate reverseProxyTemplate;

   /**
    * Attributes of the User's LDAP Object that contain role name information.
    */

   private String rolePrefix = "ROLE_";
   private boolean convertToUpperCase = true;
   
   protected Hashtable<String, GrantedAuthority[]> authContext;

   /**
    * Constructor for group search scenarios. <tt>userRoleAttributes</tt> may still be
    * set as a property.
    */
   public DefaultReverseProxyAuthoritiesPopulator(Hashtable<String, GrantedAuthority[]> authContext) {
	   this.authContext = authContext;
	   reverseProxyTemplate = new ReverseProxySearchTemplate();
   }

   /**
    * This method should be overridden if required to obtain any additional
    * roles for the given user (on top of those obtained from the standard
    * search implemented by this class).
    *
    * @param reverseProxyUser the user who's roles are required
    * @return the extra roles which will be merged with those returned by the group search
    */

   protected Set<GrantedAuthority> getAdditionalRoles(ReverseProxyUserDetails reverseProxyUser) {
       return null;
   }

   /**
    * Obtains the authorities for the user who's directory entry is represented by
    * the supplied LdapUserDetails object.
    *
    * @param userDetails the user who's authorities are required
    * @return the set of roles granted to the user.
    */
   public final GrantedAuthority[] getGrantedAuthorities(ReverseProxyUserDetails userDetails) {
	   
	   String username = userDetails.getUsername();
	   
       Set<GrantedAuthority> roles = getGroupMembershipRoles(username);

       Set<GrantedAuthority> extraRoles = getAdditionalRoles(userDetails);

       if (extraRoles != null) {
           roles.addAll(extraRoles);
       }

       if (defaultRole != null) {
           roles.add(defaultRole);
       }

       return (GrantedAuthority[]) roles.toArray(new GrantedAuthority[roles.size()]);
   }

   public Set<GrantedAuthority> getGroupMembershipRoles(String username) {
       Set<GrantedAuthority> authorities = new HashSet<GrantedAuthority>();

       GrantedAuthority[] contextAuthorities = authContext.get(username);
       
       SearchTemplate searchTemplate = new UserSearchTemplate(username);
       
       Set<String> userRoles = reverseProxyTemplate.searchForSingleAttributeValues(searchTemplate, contextAuthorities);

       if (logger.isDebugEnabled()) {
           logger.debug("Roles from search: " + userRoles);
       }

       Iterator<String> it = userRoles.iterator();

       while (it.hasNext()) {
           String role = it.next();

           if (convertToUpperCase) {
               role = role.toUpperCase();
           }

           authorities.add(new GrantedAuthorityImpl(rolePrefix + role));
       }

       return authorities;
   }

   public void setConvertToUpperCase(boolean convertToUpperCase) {
       this.convertToUpperCase = convertToUpperCase;
   }

   /**
    * The default role which will be assigned to all users.
    *
    * @param defaultRole the role name, including any desired prefix.
    */
   public void setDefaultRole(String defaultRole) {
       Assert.notNull(defaultRole, "The defaultRole property cannot be set to null");
       this.defaultRole = new GrantedAuthorityImpl(defaultRole);
   }

   public void setRolePrefix(String rolePrefix) {
       Assert.notNull(rolePrefix, "rolePrefix must not be null");
       this.rolePrefix = rolePrefix;
   }
}