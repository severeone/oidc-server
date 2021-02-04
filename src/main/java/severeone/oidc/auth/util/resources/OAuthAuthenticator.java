package severeone.oidc.auth.util.resources;

import severeone.oidc.auth.AuthConfig;
import severeone.oidc.auth.core.AccessData;
import severeone.oidc.auth.core.OAuthToken;
import severeone.oidc.auth.core.storage.AuthStorage;
import severeone.oidc.auth.db.sessions.SessionException;
import severeone.oidc.auth.tokens.AccessToken;
import severeone.oidc.auth.tokens.util.InvalidAccessToken;
import severeone.oidc.auth.tokens.util.InvalidAccessTokenKey;
import severeone.oidc.auth.util.Utilities;

import io.dropwizard.auth.AuthenticationException;
import io.dropwizard.auth.Authenticator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;

public class OAuthAuthenticator implements Authenticator<String, OAuthToken> {

    private static final Logger LOGGER = LoggerFactory.getLogger(OAuthAuthenticator.class);
    private final AuthConfig config;
    private final AuthStorage storage;

    public OAuthAuthenticator(final AuthConfig config, final AuthStorage storage) {
        this.config = config;
        this.storage = storage;
    }

    @Override
    public Optional<OAuthToken> authenticate(String accessToken) throws AuthenticationException {
        // Decrypt Access Token
        AccessToken at;
        try {
            at = AccessToken.decryptFromString(accessToken, Utilities.getToken(config.getAccessTokenKeyFilePath()));
        } catch (InvalidAccessTokenKey e) {
            String msg = "Failed to use an access token key";
            LOGGER.error(msg);
            throw new AuthenticationException(msg, e);
        } catch (InvalidAccessToken e) {
            return Optional.empty();
        }

        if (!at.issuerIsValid() || at.isExpired())
            return Optional.empty();

        // Check if this access token has been revoked
        AccessData ad;
        try {
            ad = storage.loadAccessData(at.getRefreshToken());
        } catch (SessionException e) {
            String msg = "Failed to load access session data";
            LOGGER.error(msg);
            throw new AuthenticationException(msg);
        }
        if (ad == null) {
            LOGGER.warn("AccessData is null for access token: " + accessToken + ". Possible CSRF attack ?");
            return Optional.empty();
        }

        return Optional.of(new OAuthToken(at));
    }

    //TODO: Implement caching
    public static Authenticator<String, OAuthToken> cachingAuthenticator() {
        throw new UnsupportedOperationException();
    }
}
