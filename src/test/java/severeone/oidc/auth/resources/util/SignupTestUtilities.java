package severeone.oidc.auth.resources.util;

import javax.ws.rs.client.Entity;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.Map;

import static severeone.oidc.auth.resources.AuthService.*;
import static severeone.oidc.auth.resources.AuthServiceTest.*;
import static severeone.oidc.auth.util.resources.AuthJerseyViolationExceptionMapper.ERROR;
import static severeone.oidc.auth.util.resources.AuthJerseyViolationExceptionMapper.INVALID_REQUEST;
import static org.junit.Assert.*;
import static org.junit.Assert.assertNotNull;

public class SignupTestUtilities {

    public static Response signupRequest(final String[][] params) {
        Form form = new Form();
        for (final String[] p : params) {
            form = form.param(p[0], p[1]);
        }
        return RESOURCES.target(SIGNUP_ENDPOINT).request().post(Entity.form(form));
    }

    public static void assertBadSignupRequest(final Response response) {
        assertTrue("Response should have entity", response.hasEntity());
        Map<String, String> entity = response.readEntity(Map.class);

        final String errorCode = INVALID_REQUEST;
        assertTrue("Response should have error body json parameter", entity.containsKey(ERROR));
        assertEquals("Error code should be " + errorCode, errorCode, entity.get(ERROR));

        assertEquals("Status code should be 400",
                Response.Status.BAD_REQUEST.getStatusCode(), response.getStatus());
        assertEquals("Media type should be application/json",
                MediaType.APPLICATION_JSON_TYPE, response.getMediaType());
    }

    public static void assertSuccessfulSignupRequest(final Response response) {
        assertTrue("Response should have entity", response.hasEntity());
        Map<String, String> entity = response.readEntity(Map.class);

        assertTrue("Response should have scope body json parameter", entity.containsKey(SCOPE));
        assertEquals("Scope should be " + OPENID, OPENID, entity.get(SCOPE));

        assertTrue("Response should have response_type body json parameter", entity.containsKey(RESPONSE_TYPE));
        assertEquals("Response type should be " + AUTHORIZATION_CODE, AUTHORIZATION_CODE, entity.get(RESPONSE_TYPE));

        assertTrue("Response should have client_id body json parameter", entity.containsKey(CLIENT_ID));
        assertEquals("Client ID should be " + CASE_BACKEND_CLIENT_ID, CASE_BACKEND_CLIENT_ID, entity.get(CLIENT_ID));

        assertTrue("Response should have redirect_uri body json parameter", entity.containsKey(REDIRECT_URI));
        assertEquals("Redirect URI should be " + CONFIG.getSignupCompletePage(),
                CONFIG.getSignupCompletePage(), entity.get(REDIRECT_URI));

        assertEquals("Status code should be 201",
                Response.Status.CREATED.getStatusCode(), response.getStatus());
        assertEquals("Media type should be application/json",
                MediaType.APPLICATION_JSON_TYPE, response.getMediaType());
        assertNotNull("Cache-control header should present", response.getHeaderString(CACHE_CONTROL));
        assertEquals("Cache-control header should be no-store",
                NO_STORE, response.getHeaderString(CACHE_CONTROL));
        assertNotNull("Pragma header should present", response.getHeaderString(PRAGMA));
        assertEquals("Cache-control header should be no-cache",
                NO_CACHE, response.getHeaderString(PRAGMA));
    }
}
