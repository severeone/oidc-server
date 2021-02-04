package severeone.oidc.auth.resources.util;

import severeone.oidc.auth.core.UpdateUserJson;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import java.util.Map;

import static severeone.oidc.auth.resources.AuthServiceTest.*;
import static severeone.oidc.auth.resources.AuthServiceTest.getBasicAuthorizationHeader;
import static severeone.oidc.auth.util.resources.AuthJerseyViolationExceptionMapper.ERROR;
import static severeone.oidc.auth.util.resources.AuthTokenUnauthorizedHandler.INVALID_CLIENT;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class UpdateUserTestUtilities {

    public static Response updateUserRequest(final String clientId, final String clientSecret, final String idToken,
                                             final UpdateUserJson.UserJson userJson) {
        Invocation.Builder b = RESOURCES.target(UPDATE_USER_ENDPOINT).request();
        if (clientId != null || clientSecret != null)
            b = b.header(AUTHORIZATION_HEADER, getBasicAuthorizationHeader(clientId, clientSecret));

        UpdateUserJson updateUserJson = new UpdateUserJson();
        if (idToken != null)
            updateUserJson.setSignedIDToken(idToken);
        if (userJson != null)
            updateUserJson.setUser(userJson);

        return b.post(Entity.json(updateUserJson));
    }

    public static void assertBadUpdateUserRequest(final Response response, final String errorCode) {
        assertTrue("Response should have entity", response.hasEntity());
        Map<String, String> entity = response.readEntity(Map.class);

        assertTrue("Response should have error body json parameter", entity.containsKey(ERROR));
        assertEquals("Error code should be " + errorCode, errorCode, entity.get(ERROR));

        assertEquals("Status code should be 400",
                Response.Status.BAD_REQUEST.getStatusCode(), response.getStatus());
        assertEquals("Media type should be application/json",
                MediaType.APPLICATION_JSON_TYPE, response.getMediaType());
    }

    public static void assertUnauthorizedUpdateUserRequest(final Response response) {
        assertTrue("Response should have entity", response.hasEntity());
        Map<String, String> entity = response.readEntity(Map.class);

        assertTrue("Response should have error body json parameter", entity.containsKey(ERROR));
        assertEquals("Error code should be invalid_client_error", INVALID_CLIENT, entity.get(ERROR));

        assertEquals("Status code should be 401",
                Response.Status.UNAUTHORIZED.getStatusCode(), response.getStatus());
    }

    public static void assertSuccessfulUpdateUserRequest(final Response response) {
        assertEquals("Status code should be 202",
                Response.Status.ACCEPTED.getStatusCode(), response.getStatus());
        assertEquals("Media type should be application/json",
                MediaType.APPLICATION_JSON_TYPE, response.getMediaType());
    }
}
