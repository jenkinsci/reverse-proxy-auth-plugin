package org.jenkinsci.plugins.reverse_proxy_auth.types;

import com.atlassian.crowd.exception.GroupNotFoundException;
import com.atlassian.crowd.integration.rest.service.factory.RestCrowdClientFactory;
import com.atlassian.crowd.service.client.CrowdClient;
import hudson.Extension;
import hudson.security.SecurityRealm;
import hudson.util.FormValidation;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.jenkinsci.plugins.reverse_proxy_auth.ReverseProxySecurityRealm;
import org.jenkinsci.plugins.reverse_proxy_auth.service.ProxyCrowdUserDetailsService;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.springframework.web.context.WebApplicationContext;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import static hudson.security.SecurityRealm.AUTHENTICATED_AUTHORITY;
import static hudson.security.SecurityRealm.findBean;

/**
 * Represents the Crowd authorization strategy
 */
public class CrowdAuthorizationType extends AuthorizationTypeMappingFactory {
    /**
     * The Crowd server URl
     */
    private String crowdUrl;

    /**
     * The Crowd application username
     */
    private String crowdApplicationName;

    /**
     * The Crowd application password
     */
    private String crowdApplicationPassword;

    /**
     * The {@link CrowdClient}
     */
    private transient CrowdClient crowdClient;

    /**
     * The authorities that are granted to the authenticated user.
     * It is not necessary, that the authorities will be stored in the config.xml, they blow up the config.xml
     */
    private transient GrantedAuthority[] authorities  = new GrantedAuthority[0];

    /**
     * The username retrieved from the header field, which is represented by the forwardedUser attribute.
     */
    public String retrievedUser;

    /**
     * Keeps the frequency which the authorities cache is updated per connected user.
     * The types String and Long are used for username and last time checked (in minutes) respectively.
     */
    private transient Hashtable<String, Long> authorityUpdateCache;

    /**
     * Sets an interval for updating the LDAP authorities. The interval is specified in minutes.
     */
    public final int updateInterval;

    /**
     * The authorization context
     */
    private Hashtable<String, GrantedAuthority[]> authContext;

    /**
     * Path to the groovy files which contains the injection of this authorization strategy
     */
    private static final String FILE_NAME = "types/CrowdAuthorizationType/ReverseProxyCrowdSecurityRealm.groovy";

    @DataBoundConstructor
    public CrowdAuthorizationType(String crowdUrl, String crowdApplicationName, String crowdApplicationPassword, int updateInterval) {
        this.crowdUrl = crowdUrl;
        this.crowdApplicationName = crowdApplicationName;
        this.crowdApplicationPassword = crowdApplicationPassword;
        this.updateInterval = updateInterval;

        this.crowdClient = new RestCrowdClientFactory()
                .newInstance(this.crowdUrl, this.crowdApplicationName, this.crowdApplicationPassword);

        this.authContext = new Hashtable<>();
    }

    @Override
    public GrantedAuthority[] retrieveAuthorities(String userFromHeader, HttpServletRequest r) {
        if (authContext == null) {
            authContext = new Hashtable<>();
        }

        GrantedAuthority []  storedGrants = authContext.get(userFromHeader);

        if (storedGrants != null && storedGrants.length > 1) {
            authorities = retrieveAuthoritiesIfNecessary(authorityUpdateCache, updateInterval, userFromHeader, storedGrants);
        } else {
            try {
                UserDetails userDetails = getSecurityRealm().loadUserByUsername(userFromHeader);
                authorities = userDetails.getAuthorities();

                Set<GrantedAuthority> tempLocalAuthorities = new HashSet<GrantedAuthority>(Arrays.asList(authorities));
                tempLocalAuthorities.add(AUTHENTICATED_AUTHORITY);
                authorities = tempLocalAuthorities.toArray(new GrantedAuthority[0]);

            } catch (UsernameNotFoundException e) {
                LOGGER.log(Level.WARNING, "User not found in the Crowd directory: " + e.getMessage());

                Set<GrantedAuthority> tempLocalAuthorities = new HashSet<GrantedAuthority>();
                tempLocalAuthorities.add(AUTHENTICATED_AUTHORITY);
                authorities = tempLocalAuthorities.toArray(new GrantedAuthority[0]);
            }
        }
        authContext.put(userFromHeader, authorities);

        return Collections.unmodifiableList(Arrays.asList(authorities)).toArray(new GrantedAuthority[authorities.length]);
    }

    @Override
    public SecurityRealm.SecurityComponents createUserDetailService(WebApplicationContext appContext) {
        return new SecurityRealm.SecurityComponents(findBean(AuthenticationManager.class, appContext), new ProxyCrowdUserDetailsService((ReverseProxySecurityRealm) getSecurityRealm(), appContext));
    }

    @Override
    public String getFilename() {
        return FILE_NAME;
    }

    @Override
    public Set<String> loadGroupByGroupname(String groupname) {
        Set<String> groups = new HashSet<>();
        try {
            groups.add(crowdClient.getGroup(groupname).getName());
        } catch (GroupNotFoundException g){
            String msg = String.format("Ignoring %s, isn't a group", groupname);
            LOGGER.log(Level.INFO, msg);
        } catch (Exception e) {
            String msg = String.format("Failed to search group name %s in Crowd", groupname);
            LOGGER.log(Level.SEVERE, msg, e);
        }
        return groups;
    }

    @Extension
    public static class DescriptorImpl extends AuthorizationTypeMappingFactoryDescriptor {
        public String getDisplayName() {
            return "Crowd";
        }

        public FormValidation doTestCrowdConnection(StaplerRequest req, StaplerResponse rsp,
                                                    @QueryParameter("crowdUrl") final String crowdUrl,
                                                    @QueryParameter("crowdApplicationName") final String crowdApplicationName,
                                                    @QueryParameter("crowdApplicationPassword") final String crowdApplicationPassword)
                throws IOException, ServletException {

            try {
                CrowdClient crowdClient = new RestCrowdClientFactory().newInstance(
                        crowdUrl, crowdApplicationName, crowdApplicationPassword);
                crowdClient.testConnection();
                return FormValidation.ok("Success");
            } catch (Exception e) {
                String errorMsg = "Error connecting to Crowd: " + e.getMessage();
                return FormValidation.error(errorMsg);
            }
        }

    }

    private static final Logger LOGGER = Logger.getLogger(CrowdAuthorizationType.class.getName());

}
