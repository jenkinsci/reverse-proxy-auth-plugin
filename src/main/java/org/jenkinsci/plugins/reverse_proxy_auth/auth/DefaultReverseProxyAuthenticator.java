package org.jenkinsci.plugins.reverse_proxy_auth.auth;

import java.util.logging.Level;
import java.util.logging.Logger;

import org.acegisecurity.AcegiMessageSource;
import org.acegisecurity.Authentication;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.jenkinsci.plugins.reverse_proxy_auth.ReverseProxySecurityRealm;
import org.jenkinsci.plugins.reverse_proxy_auth.ReverseProxySecurityRealm.ReverseProxyUserDetails;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.util.Assert;


/**
 * @author Wilder Rodrigues (wrodrigues@schubergphilis.com)
 */
public class DefaultReverseProxyAuthenticator implements ReverseProxyAuthenticator,  InitializingBean, MessageSourceAware{

	private static final Logger LOGGER = Logger
			.getLogger(ReverseProxySecurityRealm.class.getName());
	
	protected MessageSourceAccessor messages = AcegiMessageSource.getAccessor();
	
	private String username;
	private GrantedAuthority[] authorities;
	
	public DefaultReverseProxyAuthenticator(String username, GrantedAuthority[] authorities) {
		this.username = username;
		this.authorities = authorities;
	}
	
	public void setMessageSource(MessageSource messageSource) {
        Assert.notNull("Message source must not be null");
        this.messages = new MessageSourceAccessor(messageSource);
    }

	public void afterPropertiesSet() throws Exception {
	}

	public ReverseProxyUserDetails authenticate(String username, String password) {
		
		LOGGER.log(Level.INFO, "DefaultReverseProxyAuthenticator::authenticate ==> {0} to {1}", new Object[]{this.username, authorities});
		
		ReverseProxyUserDetails userDetails;
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		if (auth != null) {
			userDetails = (ReverseProxyUserDetails) auth.getPrincipal();
		} else {
			//do not use the username from the parameters' list. 
			auth = new UsernamePasswordAuthenticationToken(this.username, "", authorities);
			SecurityContextHolder.getContext().setAuthentication(auth);
			
			userDetails = (ReverseProxyUserDetails) auth.getPrincipal();
		}
		
		return userDetails;
	}
}