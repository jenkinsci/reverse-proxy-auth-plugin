package org.jenkinsci.plugins.reverse_proxy_auth.data;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import org.springframework.security.core.GrantedAuthority;

/**
 * @author Wilder Rodrigues (wrodrigues@schubergphilis.com)
 */
public abstract class SearchTemplate {

    protected String userOrGroup;

    public SearchTemplate(String userOrGroup) {
        this.userOrGroup = userOrGroup;
    }

    public abstract Set<String> processAuthorities(final Collection<? extends GrantedAuthority> authorities);

    /**
     * Process authorities.
     *
     * @param authorities Authorities. Can be {@code null}.
     * @return Set of group and user names
     */
    @NonNull
    protected Set<String> doProcess(final @CheckForNull Collection<? extends GrantedAuthority> authorities) {
        // TODO: refactoring: use emptySet() ?
        Set<String> authorityValues = new HashSet<String>();
        if (authorities != null) {
            for (GrantedAuthority grantedAuthority : authorities) {

                String authority = grantedAuthority.getAuthority();

                if (authority.toUpperCase().startsWith("CN=")) {
                    String groupName;
                    int index = authority.indexOf(',');
                    if (index > 0) {
                        groupName = authority.substring(3, authority.indexOf(','));
                    } else {
                        groupName = authority.substring(3, authority.length());
                    }
                    authorityValues.add(groupName);
                } else {
                    authorityValues.add(authority);
                }
            }
        }
        return authorityValues;
    }
}
