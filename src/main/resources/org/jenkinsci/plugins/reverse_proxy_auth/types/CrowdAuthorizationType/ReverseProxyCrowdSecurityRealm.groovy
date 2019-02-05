import jenkins.model.Jenkins
import org.acegisecurity.providers.ProviderManager
import org.acegisecurity.providers.anonymous.AnonymousAuthenticationProvider
import org.acegisecurity.providers.rememberme.RememberMeAuthenticationProvider
import org.jenkinsci.plugins.reverse_proxy_auth.auth.DefaultReverseProxyAuthenticator
import org.jenkinsci.plugins.reverse_proxy_auth.auth.ReverseProxyAuthenticationProvider
import org.jenkinsci.plugins.reverse_proxy_auth.service.ProxyCrowdAuthoritiesPopulator

/*
    Configure Reverse Proxy as the authentication realm.
    The 'instance' object refers to the instance of ReverseProxySecurityRealm
*/

authoritiesPopulator(ProxyCrowdAuthoritiesPopulator, instanceAuthorizationType.crowdClient) {
}

authenticator(DefaultReverseProxyAuthenticator, instance.retrievedUser, instanceAuthorizationType.authorities) {
}

authenticationManager(ProviderManager) {
    providers = [
            // talk to Reverse Proxy Authentication
            bean(ReverseProxyAuthenticationProvider,authenticator,authoritiesPopulator),

            // these providers apply everywhere
            bean(RememberMeAuthenticationProvider) {
                key = Jenkins.getInstance().getSecretKey();
            },
            // this doesn't mean we allow anonymous access.
            // we just authenticate anonymous users as such,
            // so that later authorization can reject them if so configured
            bean(AnonymousAuthenticationProvider) {
                key = "anonymous"
            }
    ]
}