package org.jenkinsci.plugins.reverse_proxy_auth.data;

import java.util.Collection;
import java.util.Set;
import org.springframework.security.core.GrantedAuthority;

/**
 * @author Wilder Rodrigues (wrodrigues@schubergphilis.com)
 */
public class UserSearchTemplate extends SearchTemplate {

    public UserSearchTemplate(String userOrGroup) {
        super(userOrGroup);
    }

    @Override
    public Set<String> processAuthorities(Collection<? extends GrantedAuthority> authorities) {
        return doProcess(authorities);
    }
}
