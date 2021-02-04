package severeone.oidc.auth.resources.util;

import severeone.oidc.auth.core.UpdateUserJson;

import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import java.util.Map;

import static severeone.oidc.auth.resources.AuthService.*;
import static severeone.oidc.auth.resources.AuthServiceTest.*;
import static severeone.oidc.auth.util.resources.AuthJerseyViolationExceptionMapper.ERROR;
import static severeone.oidc.auth.util.resources.AuthTokenUnauthorizedHandler.INVALID_CLIENT;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class ResetPasswordTestUtilities {

    public static Response resetPasswordRequest(final String clientId, final String clientSecret, final String email) {
        Invocation.Builder b = RESOURCES.target(RESET_PASSWORD_ENDPOINT).request();
        if (clientId != null || clientSecret != null)
            b = b.header(AUTHORIZATION_HEADER, getBasicAuthorizationHeader(clientId, clientSecret));
        Form form = new Form();
        if (email != null)
            form.param(EMAIL, email);
        return b.post(Entity.form(form));
    }

    public static void assertBadResetPasswordRequest(final Response response, final String errorCode) {
        assertTrue("Response should have entity", response.hasEntity());
        Map<String, String> entity = response.readEntity(Map.class);

        assertTrue("Response should have error body json parameter", entity.containsKey(ERROR));
        assertEquals("Error code should be " + errorCode, errorCode, entity.get(ERROR));

        assertEquals("Status code should be 400",
                Response.Status.BAD_REQUEST.getStatusCode(), response.getStatus());
        assertEquals("Media type should be application/json",
                MediaType.APPLICATION_JSON_TYPE, response.getMediaType());
    }

    public static void assertUnauthorizedResetPasswordRequest(final Response response) {
        assertTrue("Response should have entity", response.hasEntity());
        Map<String, String> entity = response.readEntity(Map.class);

        assertTrue("Response should have error body json parameter", entity.containsKey(ERROR));
        assertEquals("Error code should be invalid_client_error", INVALID_CLIENT, entity.get(ERROR));

        assertEquals("Status code should be 401",
                Response.Status.UNAUTHORIZED.getStatusCode(), response.getStatus());
    }

    public static void assertSuccessfulResetPasswordRequest(final Response response) {
        assertEquals("Status code should be 200",
                Response.Status.OK.getStatusCode(), response.getStatus());
        assertEquals("Media type should be application/json",
                MediaType.APPLICATION_JSON_TYPE, response.getMediaType());
    }
}
