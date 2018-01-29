package org.jenkinsci.plugins.reverse_proxy_auth.auth;

import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.acegisecurity.AcegiMessageSource;
import org.acegisecurity.Authentication;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.jenkinsci.plugins.reverse_proxy_auth.ReverseProxySecurityRealm;
import org.jenkinsci.plugins.reverse_proxy_auth.model.ReverseProxyUserDetails;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.util.Assert;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;


/**
 * @author Wilder Rodrigues (wrodrigues@schubergphilis.com)
 */
public class DefaultReverseProxyAuthenticator implements ReverseProxyAuthenticator,  InitializingBean, MessageSourceAware{

	private static final Logger LOGGER = Logger
			.getLogger(ReverseProxySecurityRealm.class.getName());

	@SuppressFBWarnings(value = "URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD", justification = "It is a part of public API :(")
	protected MessageSourceAccessor messages = AcegiMessageSource.getAccessor();

	private final String username;
	private final GrantedAuthority[] authorities;

	public DefaultReverseProxyAuthenticator(String username, @CheckForNull GrantedAuthority[] authorities) {
		this.username = username;
		this.authorities = authorities != null ? Arrays.copyOf(authorities, authorities.length) : null;
	}

	public void setMessageSource(@Nonnull MessageSource messageSource) {
		Assert.notNull("Message source must not be null");
		messages = new MessageSourceAccessor(messageSource);
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
