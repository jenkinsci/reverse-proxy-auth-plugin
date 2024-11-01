package org.jenkinsci.plugins.reverse_proxy_auth;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import java.util.Collection;
import java.util.Set;
import org.jenkinsci.plugins.reverse_proxy_auth.data.SearchTemplate;
import org.springframework.security.core.GrantedAuthority;

/**
 * @author Wilder Rodrigues (wrodrigues@schubergphilis.com)
 */
public class ReverseProxySearchTemplate {

    public Set<String> executeReadOnly(ContextExecutor ce) {
        return ce.executeWithContext();
    }

    public Set<String> searchForSingleAttributeValues(
            final SearchTemplate template, final @CheckForNull Collection<? extends GrantedAuthority> authorities) {

        class SingleAttributeSearchCallback implements ContextExecutor {

            @Override
            public Set<String> executeWithContext() {
                return template.processAuthorities(authorities);
            }
        }
        return executeReadOnly(new SingleAttributeSearchCallback());
    }
}

interface ContextExecutor {
    Set<String> executeWithContext();
}
