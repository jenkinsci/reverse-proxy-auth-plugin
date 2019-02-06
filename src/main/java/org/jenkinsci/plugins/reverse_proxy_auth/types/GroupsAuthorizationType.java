package org.jenkinsci.plugins.reverse_proxy_auth.types;

import hudson.Extension;
import hudson.security.SecurityRealm;
import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.context.SecurityContextHolder;
import org.jenkinsci.plugins.reverse_proxy_auth.ReverseProxySearchTemplate;
import org.jenkinsci.plugins.reverse_proxy_auth.ReverseProxySecurityRealm;
import org.jenkinsci.plugins.reverse_proxy_auth.data.GroupSearchTemplate;
import org.jenkinsci.plugins.reverse_proxy_auth.data.SearchTemplate;
import org.jenkinsci.plugins.reverse_proxy_auth.data.UserSearchTemplate;
import org.kohsuke.stapler.DataBoundConstructor;
import org.springframework.context.ApplicationContext;
import org.springframework.web.context.WebApplicationContext;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;

import static hudson.security.SecurityRealm.AUTHENTICATED_AUTHORITY;

/**
 * Represents the Group authorization strategy
 */
public class GroupsAuthorizationType extends AuthorizationTypeMappingFactory  {

    /**
     * Header name of the groups field.
     */
    public final String headerGroups;

    /**
     * Header name of the groups delimiter field.
     */
    public final String headerGroupsDelimiter;

    /**
     * Search Template used when the groups are in the header.
     */
    private ReverseProxySearchTemplate proxyTemplate;

    /**
     * Keeps the state of connected users and their granted authorities.
     */
    private Hashtable<String, GrantedAuthority[]> authContext = new Hashtable<>();


    /**
     * Path to the groovy files which contains the injection of this authorization strategy
     */
    private static final String FILE_NAME = "types/GroupsAuthorizationType/ReverseProxySecurityRealm.groovy";

    @DataBoundConstructor
    public GroupsAuthorizationType(String headerGroups, String headerGroupsDelimiter) {
        this.headerGroups = headerGroups;
        this.headerGroupsDelimiter = headerGroupsDelimiter;
        this.authContext = new Hashtable<>();
    }

    @Override
    public GrantedAuthority[] retrieveAuthorities(String userFromHeader, HttpServletRequest r) {
        GrantedAuthority[] authorities  = null;

        List<GrantedAuthority> localAuthorities = new ArrayList<GrantedAuthority>();
        localAuthorities.add(AUTHENTICATED_AUTHORITY);

        String groupsFromHeader = r.getHeader(headerGroups);

        if (groupsFromHeader != null) {
            StringTokenizer tokenizer = new StringTokenizer(groupsFromHeader, headerGroupsDelimiter);
            while (tokenizer.hasMoreTokens()) {
                final String token = tokenizer.nextToken().trim();
                localAuthorities.add(new GrantedAuthorityImpl(token));
            }
        }

        authorities = localAuthorities.toArray(new GrantedAuthority[0]);

        SearchTemplate searchTemplate = new UserSearchTemplate(userFromHeader);

        Set<String> foundAuthorities = proxyTemplate.searchForSingleAttributeValues(searchTemplate, authorities);
        Set<GrantedAuthority> tempLocalAuthorities = new HashSet<GrantedAuthority>();

        String[] authString = foundAuthorities.toArray(new String[0]);
        for (int i = 0; i < authString.length; i++) {
            tempLocalAuthorities.add(new GrantedAuthorityImpl(authString[i]));
        }

        authorities = tempLocalAuthorities.toArray(new GrantedAuthority[0]);
        authContext.put(userFromHeader, authorities);
        return authorities;
    }

    @Override
    public SecurityRealm.SecurityComponents createUserDetailService(WebApplicationContext appContext) {
        proxyTemplate = new ReverseProxySearchTemplate();

        return new SecurityRealm.SecurityComponents(findBean(AuthenticationManager.class, appContext), new ReverseProxySecurityRealm.ReverseProxyUserDetailsService(appContext));
    }

    @Override
    public String getFilename() {
        return FILE_NAME;
    }

    @Override
    public Set<String> loadGroupByGroupname(String groupname) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        GrantedAuthority[] authorities = authContext != null ? authContext.get(auth.getName()) : null;
        SearchTemplate searchTemplate = new GroupSearchTemplate(groupname);

        return proxyTemplate.searchForSingleAttributeValues(searchTemplate, authorities);
    }

    /**
     * Picks up the instance of the given type from the spring context.
     * If there are multiple beans of the same type or if there are none,
     * this method treats that as an {@link IllegalArgumentException}.
     *
     * This method is intended to be used to pick up a Acegi object from
     * spring once the bean definition file is parsed.
     *
     * @param context - the {@link ApplicationContext}
     */
    public static <T> T findBean(Class<T> type, ApplicationContext context) {
        Map m = context.getBeansOfType(type);
        switch(m.size()) {
            case 0:
                throw new IllegalArgumentException("No beans of "+type+" are defined");
            case 1:
                return type.cast(m.values().iterator().next());
            default:
                throw new IllegalArgumentException("Multiple beans of "+type+" are defined: "+m);
        }
    }

    @Extension
    public static class DescriptorImpl extends AuthorizationTypeMappingFactoryDescriptor {
        public String getDisplayName() {
            return "Groups";
        }
    }

}
