package severeone.oidc.auth.util.resources.process;

import severeone.oidc.auth.AuthConfig;
import severeone.oidc.auth.core.Client;
import severeone.oidc.auth.core.Session;
import severeone.oidc.auth.core.User;
import severeone.oidc.auth.core.storage.AuthStorage;
import severeone.oidc.auth.db.sessions.SessionException;
import severeone.oidc.auth.db.users.UserException;
import severeone.oidc.auth.tokens.gen.UUIDTokenGenerator;
import severeone.oidc.auth.util.Utilities;
import severeone.oidc.auth.util.resources.AuthJerseyViolationException;
import severeone.oidc.auth.util.resources.AuthJerseyViolationExceptionMapper;

import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Arrays;

import static severeone.oidc.auth.resources.AuthService.*;

public class AuthenticationProcessor extends RequestProcessor {

    public enum Mode { SIGNON, AUTHORIZE }

    private String email;
    private String password;
    private String scope;
    private String responseType;
    private String redirectUri;
    private String clientId;
    private String state;
    private String nonce;
    private String idTokenHint;
    private Mode mode;

    public AuthenticationProcessor(final AuthConfig config, final AuthStorage authStorage) {
        super(config, authStorage);
    }

    public AuthenticationProcessor credentials(final String email, final String password) {
        this.email = email;
        this.password = password;
        return this;
    }

    public AuthenticationProcessor oidc(Mode mode, final String scope, final String responseType, final String redirectUri,
                                        final String clientId, final String state, final String nonce) {
        this.scope = scope;
        this.responseType = responseType;
        this.redirectUri = redirectUri;
        this.clientId = clientId;
        this.state = state;
        this.nonce = nonce;
        this.mode = mode;
        return this;
    }

    public AuthenticationProcessor idTokenHint(final String idTokenHint) {
        this.idTokenHint = idTokenHint;
        return this;
    }

    @Override
    public Response process() {
        switch (mode) {
            case SIGNON:
                return signon();
            case AUTHORIZE:
                return authorize();
            default:
                throw new InternalServerErrorException("Unknown authentication mode");
        }
    }

    private Response signon() {
        java.net.URL redirectUriURL = validateAuthorizeParameters(scope, responseType, redirectUri, clientId, state);

        User user = authenticateEndUser(email, password, redirectUri, state);
        if (user == null)
            throw new AuthJerseyViolationException(EMAIL, redirectUri,
                    AuthJerseyViolationExceptionMapper.INVALID_REQUEST, "no credentials provided");

        // TODO: Implement obtaining End-User Consent/Authorization

        Session session = createAuthorizationSession(clientId, user.id, redirectUriURL, nonce);

        return successfulAuthenticationResponse(redirectUri, session.authorizationCode, state);
    }

    private Response authorize() {
        java.net.URL redirectUriURL = validateAuthorizeParameters(scope, responseType, redirectUri, clientId, state);

        // TODO: Implement 3rd party ID Token flow by processing ID Token hint

        User user = authenticateEndUser(email, password, redirectUri, state);
        if (user == null)
            return redirectToLoginPageResponse(scope, responseType, redirectUri, clientId, state, nonce);

        // TODO: Implement obtaining End-User Consent/Authorization

        Session session = createAuthorizationSession(clientId, user.id, redirectUriURL, nonce);

        return successfulAuthenticationResponse(redirectUri, session.authorizationCode, state);
    }

    private User authenticateEndUser(final String email, final String password, final String redirectUri,
                                     final String state) {
        if (email == null || email.isEmpty() || password == null || password.isEmpty())
            return null;

        User u;
        try {
            u = authStorage.loadUser(email);
        } catch (UserException e) {
            // TODO: Log an error
            throw new InternalServerErrorException("Failed to authenticate user with email: " + email);
        }
        if (u == null)
            throw new AuthJerseyViolationException(EMAIL, redirectUri,
                    AuthJerseyViolationExceptionMapper.INVALID_REQUEST, "no user registered with the given email", state);
        if (!Utilities.verifyHash(password, u.passwordHash))
            throw new AuthJerseyViolationException(PASSWORD, redirectUri,
                    AuthJerseyViolationExceptionMapper.INVALID_REQUEST, "invalid password provided", state);

        return u;
    }

    private Response redirectToLoginPageResponse(final String scope, final String responseType,
                                                 final String redirectUri, final String clientId,
                                                 final String state, final String nonce) {
        UriBuilder loginPageUri = UriBuilder.fromUri(config.getLoginPage())
                .queryParam(RESPONSE_TYPE, responseType)
                .queryParam(REDIRECT_URI, redirectUri)
                .queryParam(CLIENT_ID, clientId)
                .queryParam(SCOPE, scope);

        if (!state.isEmpty())
            loginPageUri.queryParam(STATE, state);
        if (!nonce.isEmpty())
            loginPageUri.queryParam(NONCE, nonce);

        return authenticationResponse(loginPageUri);
    }

    private Session createAuthorizationSession(final String clientId, int userId, final java.net.URL redirectUri,
                                               final String nonce) {
        final String authorizationCode = UUIDTokenGenerator.generate();
        final Timestamp validTill = Timestamp.from(Instant.now().plusSeconds(config.getAuthCodeLifeTime().toSeconds()));

        Session s;
        try {
            s = authStorage.saveAuthorizationData(authorizationCode, clientId, userId, redirectUri, nonce, validTill);
        } catch (SessionException |UserException e) {
            // TODO: Log an error
            throw new InternalServerErrorException("Failed to create a new authorization session");
        }
        if (s == null)
            // TODO: Log an error
            throw new InternalServerErrorException("Failed to create a new authorization session");

        return s;
    }

    private Response successfulAuthenticationResponse(final String redirectUri, final String authorizationCode,
                                                      final String state) {
        UriBuilder uri = UriBuilder.fromUri(redirectUri)
                .queryParam(AUTHORIZATION_CODE, authorizationCode);

        if (!state.isEmpty())
            uri.queryParam(STATE, state);

        return authenticationResponse(uri);
    }

    private Response authenticationResponse(UriBuilder uriBuilder) {
        return Response
                .status(Response.Status.FOUND)
                .location(uriBuilder.build())
                .type(MediaType.APPLICATION_FORM_URLENCODED)
                .build();
    }

    private java.net.URL validateAuthorizeParameters(final String scope, final String responseType,
                                                     final String redirectUri, final String clientId,
                                                     final String state) {
        // Validate Client ID and Redirect URI
        java.net.URL redirectUriURL = Client.validateClientAndRedirectUri(authStorage, clientId, redirectUri);

        // Validate response type
        if (!AUTHORIZATION_CODE.equals(responseType))
            throw new AuthJerseyViolationException(RESPONSE_TYPE, redirectUri,
                    AuthJerseyViolationExceptionMapper.UNSUPPORTED_RESPONSE_TYPE, null, state);

        // Validate scope
        if (scope == null || !Arrays.asList(scope.split(" ")).contains(OPENID))
            throw new AuthJerseyViolationException(SCOPE, redirectUri,
                    AuthJerseyViolationExceptionMapper.INVALID_SCOPE, "must contain openid value", state);

        return redirectUriURL;
    }

}
