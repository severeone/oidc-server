package severeone.oidc.auth.util.resources.process;

import severeone.oidc.auth.AuthConfig;
import severeone.oidc.auth.core.AccessData;
import severeone.oidc.auth.core.storage.AuthStorage;
import severeone.oidc.auth.db.sessions.SessionException;
import severeone.oidc.auth.tokens.AccessToken;
import severeone.oidc.auth.tokens.IDToken;
import severeone.oidc.auth.tokens.util.InvalidAccessToken;
import severeone.oidc.auth.tokens.util.InvalidAccessTokenKey;
import severeone.oidc.auth.tokens.util.InvalidIDToken;
import severeone.oidc.auth.tokens.util.InvalidIDTokenKey;
import severeone.oidc.auth.util.Utilities;
import severeone.oidc.auth.util.resources.AuthJerseyViolationException;
import severeone.oidc.auth.util.resources.AuthJerseyViolationExceptionMapper;

import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import static severeone.oidc.auth.resources.AuthService.*;

public class RevokeProcessor extends RequestProcessor {

    private String idToken;
    private String accessToken;
    private String clientId;
    private AccessToken decryptedAccessToken;

    public RevokeProcessor(final AuthConfig config, final AuthStorage authStorage) {
        super(config, authStorage);
    }

    public RevokeProcessor tokens(final String idToken, final String accessToken) {
        this.idToken = idToken;
        this.accessToken = accessToken;
        return this;
    }

    public RevokeProcessor clientId(final String clientId) {
        this.clientId = clientId;
        return this;
    }

    @Override
    public Response process() {
        validateTokens();

        removeAccessToken();

        return Response
                .status(Response.Status.ACCEPTED)
                .type(MediaType.APPLICATION_JSON)
                .build();
    }

    private void validateTokens() {
        // Validate Access Token
        if (accessToken == null)
            throw new AuthJerseyViolationException(ACCESS_TOKEN, null,
                    AuthJerseyViolationExceptionMapper.INVALID_GRANT, "is missing");

        try {
            decryptedAccessToken = AccessToken.decryptFromString(accessToken,
                    Utilities.getToken(config.getAccessTokenKeyFilePath()));
        } catch (InvalidAccessTokenKey e) {
            // TODO: Log an error
            throw new InternalServerErrorException("Failed to apply the access token key");
        } catch (InvalidAccessToken e) {
            throw new AuthJerseyViolationException(ACCESS_TOKEN, null,
                    AuthJerseyViolationExceptionMapper.INVALID_GRANT, "is corrupted");
        }

        // Validate client ID
        if (!decryptedAccessToken.clientIsValid(clientId))
            throw new AuthJerseyViolationException(CLIENT_ID, null,
                    AuthJerseyViolationExceptionMapper.UNAUTHORIZED_CLIENT, "is not authorized");
        if (decryptedAccessToken.isExpired())
            removeAccessToken();
        if (!decryptedAccessToken.isValid(clientId))
            throw new AuthJerseyViolationException(ACCESS_TOKEN, null,
                    AuthJerseyViolationExceptionMapper.INVALID_GRANT, "is not valid");

        // Validate ID Token
        if (idToken == null)
            throw new AuthJerseyViolationException(ID_TOKEN, null,
                    AuthJerseyViolationExceptionMapper.INVALID_GRANT, "is missing");

        IDToken it;
        try {
            it = IDToken.readFromString(idToken, Utilities.getToken(config.getIdTokenKeyFilePath()));
        } catch (InvalidIDTokenKey e) {
            // TODO: Log an error
            throw new InternalServerErrorException("Failed to apply the ID token key");
        } catch (InvalidIDToken e) {
            throw new AuthJerseyViolationException(ID_TOKEN, null,
                    AuthJerseyViolationExceptionMapper.INVALID_GRANT, "is corrupted");
        }

        // Validate client ID
        if (!it.clientIsValid(clientId))
            throw new AuthJerseyViolationException(CLIENT_ID, null,
                    AuthJerseyViolationExceptionMapper.UNAUTHORIZED_CLIENT, "is not authorized");
        if (!it.isValid(clientId))
            throw new AuthJerseyViolationException(ID_TOKEN, null,
                    AuthJerseyViolationExceptionMapper.INVALID_GRANT, "is not valid");
    }

    private void removeAccessToken() {
        try {
            if (!authStorage.removeAccessData(accessToken)) {
                // TODO: Log a possible CSRF attack
                AccessData ad = authStorage.loadAccessData(decryptedAccessToken.getRefreshToken());
                if (ad != null)
                    System.out.println("Failed to remove access token data: " + ad.encryptedAccessToken);
            }
        } catch (SessionException e) {
            // TODO: Log an error
            throw new InternalServerErrorException("Failed to remove an access session");
        }
    }
}
