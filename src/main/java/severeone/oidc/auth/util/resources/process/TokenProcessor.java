package severeone.oidc.auth.util.resources.process;

import severeone.oidc.auth.AuthConfig;
import severeone.oidc.auth.core.AccessData;
import severeone.oidc.auth.core.Session;
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
import severeone.oidc.auth.util.resources.AuthTokenUnauthorizedHandler;

import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import java.util.Arrays;
import java.util.HashMap;

import static severeone.oidc.auth.resources.AuthService.*;

public class TokenProcessor extends RequestProcessor {

    private String authorizationCode;
    private String redirectUri;
    private String refreshToken;
    private String clientId;
    private String scope;
    private String grantType;

    public TokenProcessor(final AuthConfig config, final AuthStorage authStorage) {
        super(config, authStorage);
    }

    public TokenProcessor authCodeFlow(final String authorizationCode, final String redirectUri) {
        this.authorizationCode = authorizationCode;
        this.redirectUri = redirectUri;
        return this;
    }

    public TokenProcessor refreshFlow(final String refreshToken, final String clientId, final String scope) {
        this.refreshToken = refreshToken;
        this.clientId = clientId;
        this.scope = scope;
        return this;
    }

    public TokenProcessor grant(final String grantType) {
        this.grantType = grantType;
        return this;
    }

    @Override
    public Response process() {
        // Validate grant type
        if (AUTHORIZATION_CODE_GRANT.equals(grantType))
            return authCode(authorizationCode, redirectUri);
        else if (REFRESH_TOKEN_GRANT.equals(grantType))
            return refresh(refreshToken, clientId, scope);
        else
            throw new AuthJerseyViolationException(GRANT_TYPE, null,
                    AuthJerseyViolationExceptionMapper.UNSUPPORTED_GRANT_TYPE, grantType);
    }

    private Response authCode(final String authorizationCode, final String redirectUri) {
        final Session session = validateTokenAuthCodeFlowParameters(authorizationCode, redirectUri);

        final AccessToken accessToken = createAccessToken(session.clientId, session.userId);
        final String accessTokenKey = Utilities.getToken(config.getAccessTokenKeyFilePath());
        final String encryptedAccessToken = encryptAccessToken(accessToken, accessTokenKey);

        createAccessSession(encryptedAccessToken, accessToken.getRefreshToken(), accessToken.getClientId(),
                session.userId);

        final String idToken = createIDToken(session.clientId, session.userId, session.nonce);

        finishAuthorizationSession(authorizationCode);

        return successfulTokenResponse(idToken, encryptedAccessToken);
    }

    private Response refresh(final String refreshToken, final String clientId, final String scope) {
        final AccessData accessData = validateTokenRefreshFlowParameters(refreshToken, clientId, scope);

        final AccessToken accessToken = createAccessToken(accessData.clientId, accessData.userId);
        final String accessTokenKey = Utilities.getToken(config.getAccessTokenKeyFilePath());
        final String encryptedAccessToken = encryptAccessToken(accessToken, accessTokenKey);

        createAccessSession(encryptedAccessToken, accessToken.getRefreshToken(), accessToken.getClientId(),
                accessData.userId);

        final String idToken = createIDToken(accessData.clientId, accessData.userId, null);

        return successfulTokenResponse(idToken, encryptedAccessToken);
    }

    private Session validateTokenAuthCodeFlowParameters(final String authorizationCode, final String redirectUri) {
        // Validate Authorization Code
        Session session;
        try {
            session = authStorage.loadAuthorizationData(authorizationCode);
        } catch (SessionException e) {
            // TODO: Log an error
            throw new InternalServerErrorException("Failed to validate an authorization code: " +
                    authorizationCode);
        }

        if (session == null)
            // TODO: Log invalid code usage
            throw new AuthJerseyViolationException(AUTHORIZATION_CODE, null,
                    AuthJerseyViolationExceptionMapper.INVALID_GRANT, "is invalid");

        if (session.isExpired()) {
            try {
                authStorage.removeAuthorizationData(authorizationCode);
            } catch (SessionException e) {
                // TODO: Log an error
            }
            throw new AuthJerseyViolationException(AUTHORIZATION_CODE, null,
                    AuthJerseyViolationExceptionMapper.INVALID_GRANT, "has expired");
        }

        // Validate redirect URI
        if (!session.redirectUri.toString().equals(redirectUri))
            throw new AuthJerseyViolationException(REDIRECT_URI, null,
                    AuthJerseyViolationExceptionMapper.INVALID_REQUEST, "is invalid");

        return session;
    }

    private AccessData validateTokenRefreshFlowParameters(final String refreshToken, final String clientId,
                                                          final String scope) {
        // Validate Refresh Token
        AccessData accessData;
        try {
            accessData = authStorage.loadAccessData(refreshToken);
        } catch (SessionException e) {
            // TODO: Log an error
            throw new InternalServerErrorException("Failed to validate a refresh token: " + refreshToken);
        }

        if (accessData == null)
            // TODO: Log invalid refresh token usage
            throw new AuthJerseyViolationException(REFRESH_TOKEN, null,
                    AuthJerseyViolationExceptionMapper.INVALID_GRANT, "is invalid");

        // Validate client ID
        if (clientId == null || !clientId.equals(accessData.clientId)) {
            throw new AuthJerseyViolationException(CLIENT_ID, null,
                    AuthTokenUnauthorizedHandler.INVALID_CLIENT, "is invalid");
        }

        // Validate scope
        if (scope != null && !Arrays.asList(scope.split(" ")).contains(OPENID))
            throw new AuthJerseyViolationException(SCOPE, null,
                    AuthJerseyViolationExceptionMapper.INVALID_SCOPE, "must contain openid value");

        try {
            authStorage.removeAccessData(accessData.encryptedAccessToken);
        } catch (SessionException e) {
            // TODO: Log an error
        }

        return accessData;
    }

    private void createAccessSession(final String accessToken, final String refreshToken,
                                     final String clientId, int userId) {
        AccessData ad;
        try {
            ad = authStorage.saveAccessData(refreshToken, accessToken, clientId, userId);
        } catch (SessionException e) {
            // TODO: Log an error
            throw new InternalServerErrorException("Failed to create a new access session");
        }
        if (ad == null)
            throw new InternalServerErrorException("Failed to create a new access session");
    }

    private Response successfulTokenResponse(final String idToken, final String accessToken) {
        return Response
                .ok()
                .header("Cache-Control", "no-store")
                .header("Pragma", "no-cache")
                .type(MediaType.APPLICATION_JSON)
                .entity(new HashMap<String, Object>() {{
                    put(ACCESS_TOKEN, accessToken);
                    put(ID_TOKEN, idToken);
                    put(TOKEN_TYPE, BEARER_TYPE);
                    put(EXPIRES_IN, config.getAccessTokenLifeTime().toSeconds());
                }})
                .build();
    }

    private String createIDToken(final String clientId, int userId, final String nonce) {
        IDToken.Builder idTokenBuilder = new IDToken.Builder()
                .clientId(clientId)
                .userId(String.valueOf(userId))
                .lifeTime(config.getIdTokenLifeTime().toSeconds())
                .claim(OPENID_PROVIDER_ORIGIN, CASE_OP);

        if (nonce != null)
            idTokenBuilder.nonce(nonce);

        final IDToken idToken = idTokenBuilder.build();
        final String idTokenKey = Utilities.getToken(config.getIdTokenKeyFilePath());

        String signedIDToken;
        try {
            signedIDToken = idToken.signToString(idTokenKey);
        } catch (InvalidIDTokenKey | InvalidIDToken e) {
            // TODO: Log an error
            throw new InternalServerErrorException("Failed to create a new access session");
        }

        return signedIDToken;
    }

    private AccessToken createAccessToken(final String clientId, int userId) {
        return new AccessToken.Builder()
                .addScope("all") // TODO: Implement different scopes
                .clientId(clientId)
                .userId(String.valueOf(userId))
                .lifeTime(config.getAccessTokenLifeTime().toSeconds())
                .build();
    }

    private String encryptAccessToken(final AccessToken accessToken, final String key) {
        String encrypted;
        try {
            encrypted = accessToken.encryptToString(key);
        } catch (InvalidAccessToken | InvalidAccessTokenKey e) {
            // TODO: Log an error
            throw new InternalServerErrorException("Failed to create a new access session");
        }
        return encrypted;
    }

    private void finishAuthorizationSession(final String authorizationCode) {
        try {
            authStorage.removeAuthorizationData(authorizationCode);
        } catch (SessionException e) {
            // TODO: Log an error
        }
        // TODO: Implement expired auth code clean up
    }
}
