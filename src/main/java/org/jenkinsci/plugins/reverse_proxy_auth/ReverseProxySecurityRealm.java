/*
 * The MIT License
 *
 * Copyright (c) 2011, CloudBees, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jenkinsci.plugins.reverse_proxy_auth;

import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.Hudson;
import hudson.security.SecurityRealm;
import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.kohsuke.stapler.DataBoundConstructor;
import org.springframework.dao.DataAccessException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.ArrayList;
import java.util.StringTokenizer;

/**
 * @author Kohsuke Kawaguchi
 */
public class ReverseProxySecurityRealm extends SecurityRealm {
    private final String userHeader;
    private final String groupsHeader;

    @DataBoundConstructor
    public ReverseProxySecurityRealm(String userHeader,
                                     String groupsHeader) {
        this.userHeader = userHeader;
        this.groupsHeader = groupsHeader;
    }

    /**
     * Name of the HTTP user header to look at.
     */
    public String getUserHeader() {
        return userHeader;
    }
    
    /**
     * Name of the HTTP groups header to look at.
     */
    public String getUserGroups() {
        return groupsHeader;
    }

    @Override
    public boolean canLogOut() {
        return false;
    }

    @Override
    public Filter createFilter(FilterConfig filterConfig) {
        return new Filter() {
            public void init(FilterConfig filterConfig) throws ServletException {
            }

            public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
                HttpServletRequest r = (HttpServletRequest) request;

                String u = r.getHeader(userHeader);
                String g = r.getHeader(groupsHeader);
                Authentication a;
                if (u==null) {
                    a = Hudson.ANONYMOUS;
                } else {
                    ArrayList<GrantedAuthority> gAuths = new ArrayList<GrantedAuthority>();
                    gAuths.add(AUTHENTICATED_AUTHORITY);
                    if(g!=null) {
                        StringTokenizer strTok = new StringTokenizer(g, ",");
                        if(strTok!=null) {
                            while(strTok.hasMoreElements()) {
                                gAuths.add(new GrantedAuthorityImpl(strTok.nextToken().trim()));
                            }
                        }
                    }
                    a = new UsernamePasswordAuthenticationToken(u,"",gAuths.toArray(new GrantedAuthority[]{}));
                }

                SecurityContextHolder.getContext().setAuthentication(a);

                chain.doFilter(request,response);
            }

            public void destroy() {
            }
        };
    }

    @Override
    public SecurityComponents createSecurityComponents() {
        return new SecurityComponents(new AuthenticationManager() {
            public Authentication authenticate(Authentication authentication) {
                return authentication;
            }
        }, new UserDetailsService() {
            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
                throw new UsernameNotFoundException(username);
            }
        });
    }

    @Extension
    public static class DescriptorImpl extends Descriptor<SecurityRealm> {
        public String getDisplayName() {
            return Messages.ReverseProxySecurityRealm_DisplayName();
        }
    }
}
