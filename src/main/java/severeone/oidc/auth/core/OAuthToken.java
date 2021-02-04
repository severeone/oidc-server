package severeone.oidc.auth.core;

import severeone.oidc.auth.tokens.AccessToken;

import java.security.Principal;

public class OAuthToken implements Principal {

    public final AccessToken accessToken;

    public OAuthToken(final AccessToken accessToken) {
        this.accessToken = accessToken;
    }

    @Override
    public String getName() {
        return accessToken.getUserId() + accessToken.getIssuedAt();
    }
}
