package org.jenkinsci.plugins.reverse_proxy_auth;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import java.util.Set;
import org.acegisecurity.GrantedAuthority;
import org.jenkinsci.plugins.reverse_proxy_auth.data.SearchTemplate;

/**
 * @author Wilder Rodrigues (wrodrigues@schubergphilis.com)
 */
public class ReverseProxySearchTemplate {

    public Set<String> executeReadOnly(ContextExecutor ce) {
        return ce.executeWithContext();
    }

    public Set<String> searchForSingleAttributeValues(
            final SearchTemplate template, final @CheckForNull GrantedAuthority[] authorities) {

        class SingleAttributeSearchCallback implements ContextExecutor {

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
