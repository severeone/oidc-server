package severeone.oidc.auth.resources;

import severeone.oidc.auth.AuthConfig;
import severeone.oidc.auth.core.*;
import severeone.oidc.auth.core.storage.AuthStorage;
import severeone.oidc.auth.core.storage.DbAuthStorage;
import severeone.oidc.auth.db.sessions.MockSessionService;
import severeone.oidc.auth.db.users.MockUserService;
import severeone.oidc.auth.db.users.UserException;
import severeone.oidc.auth.tokens.AccessToken;
import severeone.oidc.auth.tokens.IDToken;
import severeone.oidc.auth.util.Utilities;
import severeone.oidc.auth.util.resources.*;

import com.fasterxml.jackson.databind.ObjectMapper;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;

import io.dropwizard.auth.*;
import io.dropwizard.auth.basic.BasicCredentialAuthFilter;
import io.dropwizard.auth.basic.BasicCredentials;
import io.dropwizard.auth.oauth.OAuthCredentialAuthFilter;
import io.dropwizard.configuration.ConfigurationException;
import io.dropwizard.configuration.YamlConfigurationFactory;
import io.dropwizard.jackson.Jackson;
import io.dropwizard.jersey.validation.Validators;
import io.dropwizard.testing.ResourceHelpers;
import io.dropwizard.testing.junit.ResourceTestRule;

import org.apache.commons.lang3.tuple.Pair;

import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;

import javax.validation.Validator;
import javax.ws.rs.core.Response;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLDecoder;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.*;
import java.util.function.Function;
import java.util.function.Supplier;

import static severeone.oidc.auth.resources.AuthService.*;
import static severeone.oidc.auth.util.resources.AuthJerseyViolationExceptionMapper.*;
import static severeone.oidc.auth.resources.util.DeleteUserTestUtilities.*;
import static severeone.oidc.auth.resources.util.MigrateUserTestUtilities.*;
import static severeone.oidc.auth.resources.util.AuthenticationTestUtilities.*;
import static severeone.oidc.auth.resources.util.TokenTestUtilities.*;
import static severeone.oidc.auth.resources.util.SignupTestUtilities.*;
import static severeone.oidc.auth.resources.util.RevokeTestUtilities.*;
import static severeone.oidc.auth.resources.util.UserInfoTestUtilities.*;
import static severeone.oidc.auth.resources.util.UpdateUserTestUtilities.*;
import static severeone.oidc.auth.resources.util.ResetPasswordTestUtilities.*;

import static org.junit.Assert.*;

public class AuthServiceTest {

    public enum RequestMethod { GET, POST }

    public static final String SIGNON_ENDPOINT = "/auth/signon";
    public static final String AUTHORIZE_ENDPOINT = "/auth/authorize";
    public static final String TOKEN_ENDPOINT = "/auth/token";
    public static final String USERINFO_ENDPOINT = "/auth/userinfo";
    public static final String SIGNUP_ENDPOINT = "/auth/signup";
    public static final String REVOKE_ENDPOINT = "/auth/revoke";
    public static final String UPDATE_USER_ENDPOINT = "/auth/updusr";
    public static final String RESET_PASSWORD_ENDPOINT = "/auth/resetpwd";
    public static final String DELETE_USER_ENDPOINT = "/auth/qa/delete_user";
    public static final String MIGRATE_USER_ENDPOINT = "/auth/tmp/migrate_user";

    public static final String WRONG = "wrong_";
    public static final String FOR_DELETE = "delete_";
    public static final String REFRESH = "refresh_";
    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String WWW_AUTHENTICATE_HEADER = "WWW-Authenticate";
    public static final MockUserService USER_SERVICE = new MockUserService(1);
    public static final Client TEST_CLIENT = Utilities.createTestClient();
    public static final TokensLifeTime TEST_TOKENS_LIFE_TIME = Utilities.createTestTokensLifeTime();
    public static final String BASIC_AUTHORIZATION = "Basic";
    public static final String BEARER_AUTHORIZATION = "Bearer";
    public static final String CACHE_CONTROL = "Cache-control";
    public static final String NO_STORE = "no-store";
    public static final String PRAGMA = "Pragma";
    public static final String NO_CACHE = "no-cache";
    public static final AuthConfig CONFIG;
    public static final AuthStorage AUTH_STORAGE =
            new DbAuthStorage(new MockSessionService(USER_SERVICE, TEST_CLIENT, TEST_TOKENS_LIFE_TIME), USER_SERVICE);

    public static final User TEST_USER;

    static {
        User u = null;
        try {
            u = USER_SERVICE.createUser(UserType.REGULAR, "rmarsh@evil.com", "crabpeople",
                    "Randy", "Marsh");
        } catch (UserException e) {
            fail("Failed to create a test user");
        }
        TEST_USER = u;

        final ObjectMapper objectMapper = Jackson.newObjectMapper();
        final Validator validator = Validators.newValidator();
        final YamlConfigurationFactory<AuthConfig> factory =
                new YamlConfigurationFactory<>(AuthConfig.class, validator, objectMapper, "dw");
        final File yaml = new File(ResourceHelpers.resourceFilePath("config_for_test.yml"));

        AuthConfig c = null;
        try {
            c = factory.build(yaml);
        } catch (IOException | ConfigurationException e) {
            fail("Failed to load configuration: " + e.getMessage());
        } finally {
            CONFIG = c;
        }
    }

    private static final AuthFilter<BasicCredentials, Client> BASIC_CREDENTIAL_AUTH_FILTER =
            new BasicCredentialAuthFilter.Builder<Client>()
                    .setAuthenticator(new BasicAuthenticator(AUTH_STORAGE))
                    .setRealm("OpenID Connect")
                    .setPrefix("Basic")
                    .setUnauthorizedHandler(new AuthTokenUnauthorizedHandler())
                    .buildAuthFilter();

    private static final AuthFilter<String, OAuthToken> OAUTH_CREDENTIAL_AUTH_FILTER =
            new OAuthCredentialAuthFilter.Builder<OAuthToken>()
                    .setAuthenticator(new OAuthAuthenticator(CONFIG, AUTH_STORAGE))
                    .setRealm("OpenID Connect")
                    .setPrefix("Bearer")
                    .setUnauthorizedHandler(new AuthTokenUnauthorizedHandler())
                    .buildAuthFilter();

    private static final Map<String, String> params = new HashMap<String, String>(){{
        put(EMAIL, TEST_USER.email);
        put(WRONG+EMAIL, "mrcrabtree@evil.com");
        put(FOR_DELETE+EMAIL, "mrhat@evil.com");
        put(PASSWORD, "crabpeople");
        put(WRONG+PASSWORD, "manbearpig");
        put(SCOPE, "openid");
        put(WRONG+SCOPE, "allyourmoney");
        put(CLIENT_ID, TEST_CLIENT.id);
        put(WRONG+CLIENT_ID, "mscrabtree");
        put(ID_TOKEN_HINT, "id-token-hint");
        put(NONCE, "noncenoncenonce");
        put(STATE, "down");
        put(RESPONSE_TYPE, "code");
        put(WRONG+RESPONSE_TYPE, "batman");
        put(REDIRECT_URI, TEST_CLIENT.redirectUris.iterator().next().toString());
        put(WRONG+REDIRECT_URI, "http://evil.com/");
        put(GRANT_TYPE, AUTHORIZATION_CODE_GRANT);
        put(WRONG+GRANT_TYPE, "fullaccess");
        put(REFRESH+GRANT_TYPE, REFRESH_TOKEN_GRANT);
        put(FIRST_NAME, "Miss");
        put(LAST_NAME, "Crabtree");
    }};

    private String authCode;
    private AccessToken accessToken;
    private String encryptedAccessToken;
    private String signedIDToken;
    private String email;
    private String password;

    private Function<String[], String[][]> setParams = names -> {
        ArrayList<String[]> res = new ArrayList<>();
        for (String n : names) {
            if (AUTHORIZATION_CODE.equals(n))
                res.add(new String[]{n, authCode});
            else if ((WRONG+AUTHORIZATION_CODE).equals(n))
                res.add(new String[]{n, "manbearpig"});
            else if (REFRESH_TOKEN.equals(n))
                res.add(new String[]{n, accessToken.getRefreshToken()});
            else if ((WRONG+REFRESH_TOKEN).equals(n))
                res.add(new String[]{n, "mrhat"});
            else if (ACCESS_TOKEN.equals(n))
                res.add(new String[]{n, encryptedAccessToken});
            else if ((WRONG+ACCESS_TOKEN).equals(n))
                res.add(new String[]{n, "totalnonsense"});
            else if (ID_TOKEN.equals(n))
                res.add(new String[]{n, signedIDToken});
            else if ((WRONG+ID_TOKEN).equals(n))
                res.add(new String[]{n, "totalnonsense"});
            else if (n.startsWith(WRONG))
                res.add(new String[]{n.substring(WRONG.length()), params.get(n)});
            else if (n.startsWith(FOR_DELETE))
                res.add(new String[]{n.substring(FOR_DELETE.length()), params.get(n)});
            else if (EMAIL.equals(n))
                res.add(new String[]{n, email});
            else if (PASSWORD.equals(n))
                res.add(new String[]{n, password});
            else if (n.startsWith(REFRESH))
                res.add(new String[]{n.substring(REFRESH.length()), params.get(n)});
            else
                res.add(new String[]{n, params.get(n)});
        }
        String[][] arr = new String[res.size()][];
        return res.toArray(arr);
    };

    @ClassRule
    public static final ResourceTestRule RESOURCES = ResourceTestRule.builder()
            .addProvider(new PolymorphicAuthDynamicFeature<>(
                    ImmutableMap.of(
                            Client.class, BASIC_CREDENTIAL_AUTH_FILTER,
                            OAuthToken.class, OAUTH_CREDENTIAL_AUTH_FILTER)))
            .addProvider(new PolymorphicAuthValueFactoryProvider.Binder<>(
                    ImmutableSet.of(Client.class, OAuthToken.class)))
            .addProvider(new AuthJerseyViolationExceptionMapper())
            .addProvider(new AuthInternalServerErrorExceptionMapper())
            .addResource(new AuthService(CONFIG, AUTH_STORAGE))
            .build();

    @Before
    public void assignEmailAndPassword() {
        email = TEST_USER.email;
        password = "crabpeople";
    }

    @Test
    public void POST_auth_signon() {
        testAuthorize(SIGNON_ENDPOINT, RequestMethod.POST);
    }

    @Test
    public void GET_auth_authorize() {
        testAuthorize(AUTHORIZE_ENDPOINT, RequestMethod.GET);
    }

    @Test
    public void POST_auth_authorize() {
        testAuthorize(AUTHORIZE_ENDPOINT, RequestMethod.POST);
    }

    private void testAuthorize(final String endpoint, RequestMethod method) {
        // No parameters
        assertBadAuthorizeRequest(authRequest(endpoint, method, setParams.apply(new String[]{})));

        // All parameters except redirect URI
        assertBadAuthorizeRequest(authRequest(endpoint, method, setParams.apply(
                new String[]{EMAIL, PASSWORD, SCOPE, CLIENT_ID, ID_TOKEN_HINT, NONCE, STATE, RESPONSE_TYPE})));

        // Wrong redirect URI only
        assertBadAuthorizeRequest(authRequest(endpoint, method, setParams.apply(
                new String[]{WRONG+REDIRECT_URI})));

        // Redirect URI only
        assertBadAuthorizeRequest(authRequest(endpoint, method, setParams.apply(
                new String[]{REDIRECT_URI})));

        // Wrong client ID
        assertBadAuthorizeRequest(authRequest(endpoint, method, setParams.apply(
                new String[]{WRONG+CLIENT_ID})));

        // Redirect URI and wrong client ID
        assertBadAuthorizeRequest(authRequest(endpoint, method, setParams.apply(
                new String[]{WRONG+CLIENT_ID, REDIRECT_URI})));

        // Client ID and wrong redirect URI
        assertBadAuthorizeRequest(authRequest(endpoint, method, setParams.apply(
                new String[]{CLIENT_ID, WRONG+REDIRECT_URI})));

        // Client ID and redirect URI
        Response response = authRequest(endpoint, method, setParams.apply(new String[]{CLIENT_ID, REDIRECT_URI}));
        assertErrorRedirectAuthorizeRequest(response, UNSUPPORTED_RESPONSE_TYPE, splitQuery(location(response)), null);

        // Client ID, redirect URI and wrong response type
        response = authRequest(endpoint, method, setParams.apply(
                new String[]{CLIENT_ID, REDIRECT_URI, WRONG+RESPONSE_TYPE}));
        assertErrorRedirectAuthorizeRequest(response, UNSUPPORTED_RESPONSE_TYPE, splitQuery(location(response)), null);

        // Client ID, redirect URI and response type
        response = authRequest(endpoint, method, setParams.apply(
                new String[]{CLIENT_ID, REDIRECT_URI, RESPONSE_TYPE}));
        assertErrorRedirectAuthorizeRequest(response, INVALID_SCOPE, splitQuery(location(response)), null);

        // Client ID, redirect URI, response type and wrong scope
        response = authRequest(endpoint, method, setParams.apply(
                new String[]{CLIENT_ID, REDIRECT_URI, RESPONSE_TYPE, WRONG+SCOPE}));
        assertErrorRedirectAuthorizeRequest(response, INVALID_SCOPE, splitQuery(location(response)),null);

        // Client ID, redirect URI, response type and scope
        String[][] pp = setParams.apply(new String[]{CLIENT_ID, REDIRECT_URI, RESPONSE_TYPE, SCOPE});
        response = authRequest(endpoint, method, pp);
        if (AUTHORIZE_ENDPOINT.equals(endpoint))
            assertLoginRedirectAuthorizeRequest(response, splitQuery(location(response)), pp);
        else
            assertErrorRedirectAuthorizeRequest(response, INVALID_REQUEST, splitQuery(location(response)),null);

        // Client ID, redirect URI, response type, scope, id token hint, state, nonce
        pp = setParams.apply(new String[]{CLIENT_ID, REDIRECT_URI, RESPONSE_TYPE, SCOPE, STATE,
                ID_TOKEN_HINT, NONCE});
        response = authRequest(endpoint, method, pp);
        if (AUTHORIZE_ENDPOINT.equals(endpoint))
            assertLoginRedirectAuthorizeRequest(response, splitQuery(location(response)), pp);
        else
            assertErrorRedirectAuthorizeRequest(response, INVALID_REQUEST, splitQuery(location(response)),null);

        // Client ID, redirect URI, response type, scope, id token hint, state, nonce and email
        pp = setParams.apply(new String[]{CLIENT_ID, REDIRECT_URI, RESPONSE_TYPE, SCOPE, STATE,
                ID_TOKEN_HINT, NONCE, EMAIL});
        response = authRequest(endpoint, method, pp);
        if (AUTHORIZE_ENDPOINT.equals(endpoint))
            assertLoginRedirectAuthorizeRequest(response, splitQuery(location(response)), pp);
        else
            assertErrorRedirectAuthorizeRequest(response, INVALID_REQUEST, splitQuery(location(response)),null);

        // Client ID, redirect URI, response type, scope, id token hint, state, nonce and password
        pp = setParams.apply(new String[]{CLIENT_ID, REDIRECT_URI, RESPONSE_TYPE, SCOPE, STATE,
                ID_TOKEN_HINT, NONCE, PASSWORD});
        response = authRequest(endpoint, method, pp);
        if (AUTHORIZE_ENDPOINT.equals(endpoint))
            assertLoginRedirectAuthorizeRequest(response, splitQuery(location(response)), pp);
        else
            assertErrorRedirectAuthorizeRequest(response, INVALID_REQUEST, splitQuery(location(response)),null);

        // Client ID, redirect URI, response type, scope, id token hint, state, nonce, password and wrong email
        response = authRequest(endpoint, method, setParams.apply(
                new String[]{CLIENT_ID, REDIRECT_URI, RESPONSE_TYPE, SCOPE, STATE,
                        ID_TOKEN_HINT, NONCE, PASSWORD, WRONG+EMAIL}));
        assertErrorRedirectAuthorizeRequest(response, INVALID_REQUEST, splitQuery(location(response)), params.get(STATE));

        // Client ID, redirect URI, response type, scope, id token hint, state, nonce, email and wrong password
        response = authRequest(endpoint, method, setParams.apply(
                new String[]{CLIENT_ID, REDIRECT_URI, RESPONSE_TYPE, SCOPE, STATE,
                        ID_TOKEN_HINT, NONCE, WRONG+PASSWORD, EMAIL}));
        assertErrorRedirectAuthorizeRequest(response, INVALID_REQUEST, splitQuery(location(response)), params.get(STATE));

        // Client ID, redirect URI, response type, scope, id token hint, nonce, email and password
        pp = setParams.apply(new String[]{CLIENT_ID, REDIRECT_URI, RESPONSE_TYPE, SCOPE, STATE,
                ID_TOKEN_HINT, NONCE, PASSWORD, EMAIL});
        response = authRequest(endpoint, method, pp);
        assertSuccessfulRedirectAuthorizeRequest(response, splitQuery(location(response)), getParams(pp));
    }

    @Test
    public void POST_auth_token() {
        Response authResponse = authRequest(AUTHORIZE_ENDPOINT, RequestMethod.GET, setParams.apply(
                new String[]{CLIENT_ID, REDIRECT_URI, RESPONSE_TYPE, SCOPE, STATE, ID_TOKEN_HINT, NONCE, PASSWORD, EMAIL}));

        Map<String, String> authResponseParams = splitQuery(location(authResponse));
        authCode = authResponseParams.get(AUTHORIZATION_CODE);

        // No parameters
        assertUnauthorizedTokenRequest(tokenRequest(null, null, setParams.apply(new String[]{})));

        // Client ID
        assertUnauthorizedTokenRequest(tokenRequest(Utilities.CLIENT_ID, null, setParams.apply(new String[]{})));

        // Client secret
        assertUnauthorizedTokenRequest(tokenRequest(null, Utilities.CLIENT_SECRET, setParams.apply(new String[]{})));

        // Client ID and wrong client secret
        assertUnauthorizedTokenRequest(tokenRequest(Utilities.CLIENT_ID, "manbearpig", setParams.apply(new String[]{})));

        // Client ID and client secret
        assertBadTokenRequest(tokenRequest(Utilities.CLIENT_ID, Utilities.CLIENT_SECRET, setParams.apply(new String[]{})),
                UNSUPPORTED_GRANT_TYPE);

        // Client ID, client secret and wrong grant type
        assertBadTokenRequest(tokenRequest(Utilities.CLIENT_ID, Utilities.CLIENT_SECRET, setParams.apply(
                new String[]{WRONG+GRANT_TYPE})), UNSUPPORTED_GRANT_TYPE);

        //////////////////////
        // Auth Code requests
        //////////////////////

        // Client ID, client secret and grant type
        assertBadTokenRequest(tokenRequest(Utilities.CLIENT_ID, Utilities.CLIENT_SECRET, setParams.apply(
                new String[]{GRANT_TYPE})), INVALID_GRANT);

        // Client ID, client secret, grant type and wrong authorization code
        assertBadTokenRequest(tokenRequest(Utilities.CLIENT_ID, Utilities.CLIENT_SECRET, setParams.apply(
                new String[]{GRANT_TYPE, WRONG+AUTHORIZATION_CODE})), INVALID_GRANT);

        // Client ID, client secret, grant type and expired authorization code
        Supplier<Instant> plusDay = () ->  Instant.now().plusSeconds(3600*24);
        Session.setNow(plusDay);
        assertBadTokenRequest(tokenRequest(Utilities.CLIENT_ID, Utilities.CLIENT_SECRET, setParams.apply(
                new String[]{GRANT_TYPE, AUTHORIZATION_CODE})), INVALID_GRANT);

        // Client ID, client secret, grant type and deleted authorization code
        Session.setNow(Instant::now);
        assertBadTokenRequest(tokenRequest(Utilities.CLIENT_ID, Utilities.CLIENT_SECRET, setParams.apply(
                new String[]{GRANT_TYPE, AUTHORIZATION_CODE})), INVALID_GRANT);

        // Issue a new code
        authResponse = authRequest(AUTHORIZE_ENDPOINT, RequestMethod.GET, setParams.apply(
                new String[]{CLIENT_ID, REDIRECT_URI, RESPONSE_TYPE, SCOPE, STATE, ID_TOKEN_HINT, NONCE, PASSWORD, EMAIL}));
        authResponseParams = splitQuery(location(authResponse));
        authCode = authResponseParams.get(AUTHORIZATION_CODE);

        // Client ID, client secret, grant type and authorization code
        assertBadTokenRequest(tokenRequest(Utilities.CLIENT_ID, Utilities.CLIENT_SECRET, setParams.apply(
                new String[]{GRANT_TYPE, AUTHORIZATION_CODE})), INVALID_REQUEST);

        // Client ID, client secret, grant type, authorization code and invalid redirect URI
        assertBadTokenRequest(tokenRequest(Utilities.CLIENT_ID, Utilities.CLIENT_SECRET, setParams.apply(
                new String[]{GRANT_TYPE, AUTHORIZATION_CODE, WRONG+REDIRECT_URI})), INVALID_REQUEST);

        // Client ID, client secret, grant type, authorization code, redirect uri
        Pair<AccessToken, IDToken> tokens = assertSuccessfulTokenResponse(tokenRequest(Utilities.CLIENT_ID,
                Utilities.CLIENT_SECRET, setParams.apply(new String[]{GRANT_TYPE, AUTHORIZATION_CODE, REDIRECT_URI})),
                params,true);
        accessToken = tokens.getLeft();

        // Client ID, client secret, grant type, redirect uri and already used authorization code
        assertBadTokenRequest(tokenRequest(Utilities.CLIENT_ID, Utilities.CLIENT_SECRET, setParams.apply(
                new String[]{GRANT_TYPE, AUTHORIZATION_CODE, REDIRECT_URI})), INVALID_GRANT);

        ////////////////////
        // Refresh requests
        ////////////////////

        // Client ID, client secret and grant type
        assertBadTokenRequest(tokenRequest(Utilities.CLIENT_ID, Utilities.CLIENT_SECRET, setParams.apply(
                new String[]{REFRESH+GRANT_TYPE})), INVALID_GRANT);

        // Client ID, client secret, grant type and wrong refresh token
        assertBadTokenRequest(tokenRequest(Utilities.CLIENT_ID, Utilities.CLIENT_SECRET, setParams.apply(
                new String[]{REFRESH+GRANT_TYPE, WRONG+REFRESH_TOKEN})), INVALID_GRANT);

        // Client ID, client secret, grant type, refresh token and wrong scope
        assertBadTokenRequest(tokenRequest(Utilities.CLIENT_ID, Utilities.CLIENT_SECRET, setParams.apply(
                new String[]{REFRESH+GRANT_TYPE, REFRESH_TOKEN, WRONG+SCOPE})), INVALID_SCOPE);

        // Client ID, client secret, grant type, refresh token and scope
        assertSuccessfulTokenResponse(tokenRequest(Utilities.CLIENT_ID, Utilities.CLIENT_SECRET,
                setParams.apply(new String[]{REFRESH+GRANT_TYPE, REFRESH_TOKEN, SCOPE})), params,false);

        // Client ID, client secret, grant type, already used refresh token and scope
        assertBadTokenRequest(tokenRequest(Utilities.CLIENT_ID, Utilities.CLIENT_SECRET, setParams.apply(
                new String[]{REFRESH+GRANT_TYPE, REFRESH_TOKEN, SCOPE})), INVALID_GRANT);
    }

    @Test
    public void POST_auth_signup() {
        // No parameters
        assertBadSignupRequest(signupRequest(setParams.apply(new String[]{})));

        // First name and last name
        assertBadSignupRequest(signupRequest(setParams.apply(new String[]{FIRST_NAME, LAST_NAME})));

        // First name, last name and email
        assertBadSignupRequest(signupRequest(setParams.apply(new String[]{EMAIL, FIRST_NAME, LAST_NAME})));

        // First name, last name and password
        assertBadSignupRequest(signupRequest(setParams.apply(new String[]{PASSWORD, FIRST_NAME, LAST_NAME})));

        // First name, last name, email and password
        assertSuccessfulSignupRequest(signupRequest(setParams.apply(
                new String[]{WRONG+EMAIL, PASSWORD, FIRST_NAME, LAST_NAME})));

        // First name, last name, duplicate email and password
        assertBadSignupRequest(signupRequest(setParams.apply(
                new String[]{WRONG+EMAIL, PASSWORD, FIRST_NAME, LAST_NAME})));
    }

    @Test
    public void POST_auth_revoke() {
        getTokens();

        // No parameters
        assertUnauthorizedRevokeRequest(revokeRequest(null, null, setParams.apply(new String[]{})));

        // Client ID
        assertUnauthorizedRevokeRequest(revokeRequest(Utilities.CLIENT_ID, null, setParams.apply(new String[]{})));

        // Client secret
        assertUnauthorizedRevokeRequest(revokeRequest(null, Utilities.CLIENT_SECRET, setParams.apply(new String[]{})));

        // Client ID and wrong client secret
        assertUnauthorizedRevokeRequest(revokeRequest(Utilities.CLIENT_ID, "manbearpig", setParams.apply(new String[]{})));

        // Client ID and client secret
        assertBadRevokeRequest(revokeRequest(Utilities.CLIENT_ID, Utilities.CLIENT_SECRET, setParams.apply(new String[]{})),
                INVALID_GRANT);

        // Client ID, client secret and wrong access token
        assertBadRevokeRequest(revokeRequest(Utilities.CLIENT_ID, Utilities.CLIENT_SECRET,
                setParams.apply(new String[]{WRONG+ACCESS_TOKEN})), INVALID_GRANT);

        // Client ID, client secret and access token
        assertBadRevokeRequest(revokeRequest(Utilities.CLIENT_ID, Utilities.CLIENT_SECRET,
                setParams.apply(new String[]{ACCESS_TOKEN})), INVALID_GRANT);

        // Client ID, client secret, access token and ID token
        assertBadRevokeRequest(revokeRequest(Utilities.CLIENT_ID, Utilities.CLIENT_SECRET,
                setParams.apply(new String[]{ACCESS_TOKEN, WRONG+ID_TOKEN})), INVALID_GRANT);

        // Client ID, client secret, access token and ID token
        assertSuccessfulRevokeRequest(revokeRequest(Utilities.CLIENT_ID, Utilities.CLIENT_SECRET,
                setParams.apply(new String[]{ACCESS_TOKEN, ID_TOKEN})));

        // Client ID, client secret, revoked access token and ID token
        assertSuccessfulRevokeRequest(revokeRequest(Utilities.CLIENT_ID, Utilities.CLIENT_SECRET,
                setParams.apply(new String[]{ACCESS_TOKEN, ID_TOKEN})));
    }

    @Test
    public void GET_auth_userinfo() {
        userinfo(RequestMethod.GET);
    }

    @Test
    public void POST_auth_userinfo() {
        userinfo(RequestMethod.POST);
    }

    private void userinfo(RequestMethod method) {
        getTokens();

        // No parameters
        assertUnauthorizedUserInfoRequest(userInfoRequest(method, null));

        // Wrong access token
        assertUnauthorizedUserInfoRequest(userInfoRequest(method, "totalnonsense"));

        // Access token
        assertSuccessfulUserInfoRequest(userInfoRequest(method, encryptedAccessToken), TEST_USER);

        // Revoke tokens
        revokeRequest(Utilities.CLIENT_ID, Utilities.CLIENT_SECRET, setParams.apply(
                new String[]{ACCESS_TOKEN, ID_TOKEN}));

        // Revoked access token. In theory it can only happen in case of CSRF attack.
        assertUnauthorizedUserInfoRequest(userInfoRequest(method, encryptedAccessToken));
    }

    @Test
    public void POST_auth_updusr() {
        email = "mrhat@evil.com";
        password = "123456";
        final String firstName = "Mr";
        final String lastName = "H";

        ArrayList<String[]> pp = new ArrayList<String[]>() {{
            add(new String[]{EMAIL, email});
            add(new String[]{PASSWORD, password});
            add(new String[]{FIRST_NAME, firstName});
            add(new String[]{LAST_NAME, lastName});
        }};
        String[][] params = new String[pp.size()][];
        params = pp.toArray(params);

        // Register a new user
        assertSuccessfulSignupRequest(signupRequest(params));

        // Sign in
        getTokens();

        // No parameters
        assertUnauthorizedUpdateUserRequest(updateUserRequest(null, null, null, null));

        // Client ID
        assertUnauthorizedUpdateUserRequest(updateUserRequest(Utilities.CLIENT_ID, null,null, null));

        // Client secret
        assertUnauthorizedUpdateUserRequest(updateUserRequest(null, Utilities.CLIENT_SECRET, null, null));

        // Client ID and wrong client secret
        assertUnauthorizedUpdateUserRequest(updateUserRequest(Utilities.CLIENT_ID, "manbearpig", null, null));

        // Client ID and client secret
        assertBadUpdateUserRequest(updateUserRequest(Utilities.CLIENT_ID, Utilities.CLIENT_SECRET,null,
                null), INVALID_GRANT);

        // Client ID, client secret and wrong ID token
        assertBadUpdateUserRequest(updateUserRequest(Utilities.CLIENT_ID, Utilities.CLIENT_SECRET, "totalnonsense",
                null), INVALID_GRANT);

        // Client ID, client secret and ID token
        assertBadUpdateUserRequest(updateUserRequest(Utilities.CLIENT_ID, Utilities.CLIENT_SECRET, signedIDToken,
                null), INVALID_REQUEST);

        // Client ID, client secret, ID token and wrong password
        assertBadUpdateUserRequest(updateUserRequest(Utilities.CLIENT_ID, Utilities.CLIENT_SECRET, signedIDToken,
                UpdateUserJson.newUserJson(null, "crabpeople", null, null, "fancypassword")),
                INVALID_GRANT);

        // Client ID, client secret, ID token and duplicate new email
        assertBadUpdateUserRequest(updateUserRequest(Utilities.CLIENT_ID, Utilities.CLIENT_SECRET, signedIDToken,
                UpdateUserJson.newUserJson(TEST_USER.email, password, null, null, "fancypassword")),
                INVALID_REQUEST);

        // Client ID, client secret, ID token and empty new email
        assertBadUpdateUserRequest(updateUserRequest(Utilities.CLIENT_ID, Utilities.CLIENT_SECRET, signedIDToken,
                UpdateUserJson.newUserJson("", password, null, null, null)),
                INVALID_REQUEST);

        // Client ID, client secret, ID token and empty new password
        assertBadUpdateUserRequest(updateUserRequest(Utilities.CLIENT_ID, Utilities.CLIENT_SECRET, signedIDToken,
                UpdateUserJson.newUserJson(email, password, null, null, "")),
                INVALID_REQUEST);

        final String newEmail = "mrhat@evil.com";
        final String newPassword = "123456";
        final String newFirstName = "Mr";
        final String newLastName = "H";

        // Client ID, client secret, ID token and valid new user info
        assertSuccessfulUpdateUserRequest(updateUserRequest(Utilities.CLIENT_ID, Utilities.CLIENT_SECRET, signedIDToken,
                UpdateUserJson.newUserJson(newEmail, password, newFirstName, newLastName, newPassword)));

        // Check if user data was actually updated
        assertSuccessfulUserInfoRequest(userInfoRequest(RequestMethod.POST, encryptedAccessToken),
                new User(123, UserType.REGULAR, newEmail, newFirstName, newLastName, Utilities.hash(newPassword),
                        Timestamp.from(Instant.now())));
    }

    @Test
    public void POST_auth_resetpwd() {
        // No parameters
        assertUnauthorizedResetPasswordRequest(resetPasswordRequest(null, null, null));

        // Client ID
        assertUnauthorizedResetPasswordRequest(resetPasswordRequest(Utilities.CLIENT_ID, null,null));

        // Client secret
        assertUnauthorizedResetPasswordRequest(resetPasswordRequest(null, Utilities.CLIENT_SECRET, null));

        // Client ID and wrong client secret
        assertUnauthorizedResetPasswordRequest(resetPasswordRequest(Utilities.CLIENT_ID, "manbearpig", null));

        // Client ID and client secret
        assertBadResetPasswordRequest(resetPasswordRequest(Utilities.CLIENT_ID, Utilities.CLIENT_SECRET,null),
                INVALID_REQUEST);

        // Client ID, client secret and not registered email
        assertBadResetPasswordRequest(resetPasswordRequest(Utilities.CLIENT_ID, Utilities.CLIENT_SECRET,
                "professor.chaos@evil.com"), INVALID_REQUEST);

        // TODO: Implement successful response test
        // Client ID, client secret and not registered email
//        assertSuccessfulResetPasswordRequest(resetPasswordRequest(Utilities.CLIENT_ID, Utilities.CLIENT_SECRET,
//                TEST_USER.email));
    }

    @Test
    public void GET_auth_qa_delete_user() {
        final String adminToken = Utilities.getToken(CONFIG.getAdminTokenFilePath());

        // No parameters
        assertBadDeleteUserRequest(deleteUserRequest(null, null), INVALID_GRANT);

        // Invalid admin token
        assertBadDeleteUserRequest(deleteUserRequest("totalnonsense", null), INVALID_GRANT);

        // Admin token
        assertBadDeleteUserRequest(deleteUserRequest(adminToken, null), INVALID_REQUEST);

        // Admin token and not existing email
        assertBadDeleteUserRequest(deleteUserRequest(adminToken, params.get(FOR_DELETE+EMAIL)), INVALID_REQUEST);

        // Register a new user
        assertSuccessfulSignupRequest(signupRequest(setParams.apply(
                new String[]{FOR_DELETE+EMAIL, PASSWORD, FIRST_NAME, LAST_NAME})));

        // Admin token and valid email
        assertSuccessfulDeleteUserRequest(deleteUserRequest(adminToken, params.get(FOR_DELETE+EMAIL)));

        // Admin token and deleted email
        assertBadDeleteUserRequest(deleteUserRequest(adminToken, params.get(FOR_DELETE+EMAIL)), INVALID_REQUEST);
    }

    private static int emailModifier = 0;

    @Test
    public void POST_auth_tmp_migrate_user() {
        // No parameters
        assertBadMigrateRequest(migrateRequest(null, null, null));

        // Empty email
        assertBadMigrateRequest(migrateRequest("", null, null));

        // Valid email, first name and last name
        final String email = String.format("randy.marsh+%d@sp.com", ++emailModifier);
        final String resetCode = assertSuccessfulMigrateRequest(
                migrateRequest(email, "Randy", "Marsh"), AUTH_STORAGE);

        // Registered email
        assertBadMigrateRequest(migrateRequest(email, null, null));
    }

    private void getTokens() {
        // Issue a new auth code
        Response authResponse = authRequest(AUTHORIZE_ENDPOINT, RequestMethod.GET, setParams.apply(
                new String[]{CLIENT_ID, REDIRECT_URI, RESPONSE_TYPE, SCOPE, STATE, ID_TOKEN_HINT, NONCE, PASSWORD, EMAIL}));
        Map<String, String> authResponseParams = splitQuery(location(authResponse));
        authCode = authResponseParams.get(AUTHORIZATION_CODE);

        // Issue a new pair of tokens
        Response tokenResponse = tokenRequest(Utilities.CLIENT_ID,
                Utilities.CLIENT_SECRET, setParams.apply(new String[]{GRANT_TYPE, AUTHORIZATION_CODE, REDIRECT_URI}));
        Map<String, String> entity = tokenResponse.readEntity(Map.class);
        encryptedAccessToken = entity.get(ACCESS_TOKEN);
        signedIDToken = entity.get(ID_TOKEN);
    }

    private static Map<String, String> getParams(final String[][] params) {
        final Map<String, String> res = new HashMap<>();
        for (String[] param : params) {
            res.put(param[0], param[1]);
        }
        return res;
    }

    private static Map<String, String> splitQuery(URI uri) {
        try {
            final Map<String, String> queryPairs = new HashMap<>();
            final String[] pairs = uri.getQuery().split("&");
            for (final String pair : pairs) {
                final int idx = pair.indexOf("=");
                final String key = idx > 0 ? URLDecoder.decode(pair.substring(0, idx), "UTF-8") : pair;
                final String value = idx > 0 && pair.length() > idx + 1
                        ? URLDecoder.decode(pair.substring(idx + 1), "UTF-8") : null;
                queryPairs.put(key, value);
            }
            return queryPairs;
        } catch (UnsupportedEncodingException e) {
            fail("Failed to decode URL");
        }
        return null;
    }

    public static String getBasicAuthorizationHeader(final String clientId, final String clientSecret) {
        final String credentials = clientId + ":" + clientSecret;
        return BASIC_AUTHORIZATION + " " + Base64.getEncoder().encodeToString(credentials.getBytes());
    }

    public static String getBearerAuthorizationHeader(final String accessToken) {
        return BEARER_AUTHORIZATION + " " + accessToken;
    }
}