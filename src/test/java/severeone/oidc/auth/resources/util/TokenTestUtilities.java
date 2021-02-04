package severeone.oidc.auth.resources.util;

import severeone.oidc.auth.tokens.AccessToken;
import severeone.oidc.auth.tokens.IDToken;
import severeone.oidc.auth.tokens.util.InvalidAccessToken;
import severeone.oidc.auth.tokens.util.InvalidAccessTokenKey;
import severeone.oidc.auth.tokens.util.InvalidIDToken;
import severeone.oidc.auth.tokens.util.InvalidIDTokenKey;
import severeone.oidc.auth.util.Utilities;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.text.ParseException;
import java.util.Map;

import static severeone.oidc.auth.resources.AuthService.*;
import static severeone.oidc.auth.resources.AuthService.EXPIRES_IN;
import static severeone.oidc.auth.resources.AuthServiceTest.*;
import static severeone.oidc.auth.util.resources.AuthJerseyViolationExceptionMapper.ERROR;
import static severeone.oidc.auth.util.resources.AuthTokenUnauthorizedHandler.INVALID_CLIENT;
import static org.junit.Assert.*;
import static org.junit.Assert.assertEquals;

public class TokenTestUtilities {

    public static Response tokenRequest(final String clientId, final String clientSecret, final String[][] params) {
        Form form = new Form();
        for (final String[] p : params) {
            form = form.param(p[0], p[1]);
        }
        Invocation.Builder b = RESOURCES.target(TOKEN_ENDPOINT).request();
        if (clientId != null || clientSecret != null)
            b = b.header(AUTHORIZATION_HEADER, getBasicAuthorizationHeader(clientId, clientSecret));
        return b.post(Entity.form(form));
    }

    public static Pair<AccessToken, IDToken> assertSuccessfulTokenResponse(final Response response,
                                                                           final Map<String, String> params,
                                                                           boolean assertNonce) {
        assertTrue("Response should have entity", response.hasEntity());
        Map<String, String> entity = response.readEntity(Map.class);

        assertTrue("Response should have access_token body json parameter", entity.containsKey(ACCESS_TOKEN));
        AccessToken accessToken = null;
        try {
            accessToken = AccessToken.decryptFromString(entity.get(ACCESS_TOKEN), getAccessTokenKey());
        } catch (InvalidAccessToken | InvalidAccessTokenKey e) {
            fail("Failed to decrypt the given access token");
        }
        assertNotNull("Access token should be decryptable", accessToken);
        assertTrue("Access token should be valid", accessToken.isValid(Utilities.CLIENT_ID));

        assertTrue("Response should have token_type body json parameter", entity.containsKey(TOKEN_TYPE));
        assertEquals("Token type should be " + BEARER_TYPE, BEARER_TYPE, entity.get(TOKEN_TYPE));

        assertTrue("Response should have id_token body json parameter", entity.containsKey(ID_TOKEN));
        IDToken idToken = null;
        try {
            idToken = IDToken.readFromString(entity.get(ID_TOKEN), getIDTokenKey());
        } catch (InvalidIDToken | InvalidIDTokenKey e) {
            fail("Failed to read the given id token");
        }
        assertNotNull("ID token should be readable", idToken);
        if (assertNonce)
            assertTrue("ID token should be valid", idToken.isValid(Utilities.CLIENT_ID, params.get(NONCE)));
        else
            assertTrue("ID token should be valid", idToken.isValid(Utilities.CLIENT_ID));

        String origin = null;
        try {
            origin = idToken.getClaim(String.class, OPENID_PROVIDER_ORIGIN);
        } catch (ParseException e) {
            fail("Failed to get openid provider origin claim");
        }
        assertEquals("ID token should contain openid provider origin claim", CASE_OP, origin);

        assertEquals("Status code should be 200",
                Response.Status.OK.getStatusCode(), response.getStatus());

        assertTrue("Response should have expires_in body json parameter", entity.containsKey(EXPIRES_IN));
        assertEquals("Expires in should be " + CONFIG.getAccessTokenLifeTime().toSeconds(),
                (int)CONFIG.getAccessTokenLifeTime().toSeconds(), entity.get(EXPIRES_IN));

        assertTokenResponseHeaders(response);

        return new ImmutablePair<>(accessToken, idToken);
    }

    public static void assertTokenResponseHeaders(final Response response) {
        assertNotNull("Cache-control header should present", response.getHeaderString(CACHE_CONTROL));
        assertEquals("Cache-control header should be no-store",
                NO_STORE, response.getHeaderString(CACHE_CONTROL));
        assertNotNull("Pragma header should present", response.getHeaderString(PRAGMA));
        assertEquals("Cache-control header should be no-cache",
                NO_CACHE, response.getHeaderString(PRAGMA));
        assertEquals("Media type should be application/json",
                MediaType.APPLICATION_JSON_TYPE, response.getMediaType());
    }

    public static void assertBadTokenRequest(final Response response, final String errorCode) {
        assertTrue("Response should have entity", response.hasEntity());
        Map<String, String> entity = response.readEntity(Map.class);

        assertTrue("Response should have error body json parameter", entity.containsKey(ERROR));
        assertEquals("Error code should be " + errorCode, errorCode, entity.get(ERROR));

        assertEquals("Status code should be 400",
                Response.Status.BAD_REQUEST.getStatusCode(), response.getStatus());

        assertTokenResponseHeaders(response);
    }

    public static void assertUnauthorizedTokenRequest(final Response response) {
        assertTrue("Response should have entity", response.hasEntity());
        Map<String, String> entity = response.readEntity(Map.class);

        assertTrue("Response should have error body json parameter", entity.containsKey(ERROR));
        assertEquals("Error code should be invalid_client_error", INVALID_CLIENT, entity.get(ERROR));

        assertEquals("Status code should be 401",
                Response.Status.UNAUTHORIZED.getStatusCode(), response.getStatus());

        assertTokenResponseHeaders(response);
    }

    public static String getAccessTokenKey() {
        return Utilities.getToken(CONFIG.getAccessTokenKeyFilePath());
    }

    public static String getIDTokenKey() {
        return Utilities.getToken(CONFIG.getIdTokenKeyFilePath());
    }
}
