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

import java.util.StringTokenizer;
import java.util.List;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.lang.StringUtils;

/**
 * @author Kohsuke Kawaguchi
 */
public class ReverseProxySecurityRealm extends SecurityRealm {
    private static final Logger LOGGER = Logger.getLogger(ReverseProxySecurityRealm.class.getName());

    private final String header;
    private final String headerGroups;
    private final String headerGroupsDelimiter;

    @DataBoundConstructor
	public ReverseProxySecurityRealm(String header, String headerGroups, String headerGroupsDelimiter) {
        this.header = header;

        this.headerGroups = headerGroups;       
        if (StringUtils.isBlank(this.headerGroupsDelimiter)) {
            this.headerGroupsDelimiter = ",";
        }
        else {
            this.headerGroupsDelimiter = headerGroupsDelimiter;
        }
    }

    /**
     * Name of the HTTP header to look at.
     */
    public String getHeader() {
        return header;
    }

    public String getHeaderGroups() {
        return headerGroups;
    }

    public String getHeaderGroupsDelimiter() {
        return headerGroupsDelimiter;
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

                String username = r.getHeader(header);

                String groups = r.getHeader(headerGroups);
                /* String groups = "GROUPS"; */ /* BUG - At the first time, headerGroups in undefined ?!? */
 
                Authentication a;

		if (username==null) {
                    a = Hudson.ANONYMOUS;
                } else {
		    List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
		    authorities.add(AUTHENTICATED_AUTHORITY);

		    if (groups!=null) {		    
			StringTokenizer tokenizer = new StringTokenizer(groups, headerGroupsDelimiter);
			/* StringTokenizer tokenizer = new StringTokenizer(groups, ","); */ /* BUG At the first time, headerGroupsDelimiter is undefined ?!? */
			while (tokenizer.hasMoreTokens()) {
			    final String token = tokenizer.nextToken().trim();
			    String[] args = new String[] { token, username };
			    LOGGER.log(Level.FINE, "granting: {0} to {1}", args);
			    authorities.add(new GrantedAuthorityImpl(token));
			}
		    }

                    a = new UsernamePasswordAuthenticationToken(username,"", authorities.toArray(new GrantedAuthority[0]));
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
