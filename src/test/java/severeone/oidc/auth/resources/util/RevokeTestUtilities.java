package severeone.oidc.auth.resources.util;

import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.Map;

import static severeone.oidc.auth.resources.AuthServiceTest.*;
import static severeone.oidc.auth.resources.AuthServiceTest.AUTHORIZATION_HEADER;
import static severeone.oidc.auth.util.resources.AuthJerseyViolationExceptionMapper.ERROR;
import static severeone.oidc.auth.util.resources.AuthTokenUnauthorizedHandler.INVALID_CLIENT;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class RevokeTestUtilities {

    public static Response revokeRequest(final String clientId, final String clientSecret, final String[][] params) {
        Form form = new Form();
        for (final String[] p : params) {
            form = form.param(p[0], p[1]);
        }
        Invocation.Builder b = RESOURCES.target(REVOKE_ENDPOINT).request();
        if (clientId != null || clientSecret != null)
            b = b.header(AUTHORIZATION_HEADER, getBasicAuthorizationHeader(clientId, clientSecret));
        return b.post(Entity.form(form));
    }

    public static void assertBadRevokeRequest(final Response response, final String errorCode) {
        assertTrue("Response should have entity", response.hasEntity());
        Map<String, String> entity = response.readEntity(Map.class);

        assertTrue("Response should have error body json parameter", entity.containsKey(ERROR));
        assertEquals("Error code should be " + errorCode, errorCode, entity.get(ERROR));

        assertEquals("Status code should be 400",
                Response.Status.BAD_REQUEST.getStatusCode(), response.getStatus());
        assertEquals("Media type should be application/json",
                MediaType.APPLICATION_JSON_TYPE, response.getMediaType());
    }

    public static void assertUnauthorizedRevokeRequest(final Response response) {
        assertTrue("Response should have entity", response.hasEntity());
        Map<String, String> entity = response.readEntity(Map.class);

        assertTrue("Response should have error body json parameter", entity.containsKey(ERROR));
        assertEquals("Error code should be invalid_client_error", INVALID_CLIENT, entity.get(ERROR));

        assertEquals("Status code should be 401",
                Response.Status.UNAUTHORIZED.getStatusCode(), response.getStatus());
    }

    public static void assertSuccessfulRevokeRequest(final Response response) {
        assertEquals("Status code should be 202",
                Response.Status.ACCEPTED.getStatusCode(), response.getStatus());
        assertEquals("Media type should be application/json",
                MediaType.APPLICATION_JSON_TYPE, response.getMediaType());
    }
}
