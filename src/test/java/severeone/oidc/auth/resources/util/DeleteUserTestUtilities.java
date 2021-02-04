package severeone.oidc.auth.resources.util;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.Map;

import static severeone.oidc.auth.resources.AuthService.*;
import static severeone.oidc.auth.resources.AuthServiceTest.*;
import static severeone.oidc.auth.util.resources.AuthJerseyViolationExceptionMapper.ERROR;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class DeleteUserTestUtilities {

    public static Response deleteUserRequest(final String adminToken, final String email) {
        return RESOURCES
                .target(DELETE_USER_ENDPOINT)
                .queryParam(ADMIN_TOKEN, adminToken)
                .queryParam(EMAIL, email)
                .request()
                .get();
    }

    public static void assertBadDeleteUserRequest(final Response response, final String errorCode) {
        assertTrue("Response should have entity", response.hasEntity());
        Map<String, String> entity = response.readEntity(Map.class);

        assertTrue("Response should have error body json parameter", entity.containsKey(ERROR));
        assertEquals("Error code should be " + errorCode, errorCode, entity.get(ERROR));

        assertEquals("Status code should be 400",
                Response.Status.BAD_REQUEST.getStatusCode(), response.getStatus());
        assertEquals("Media type should be application/json",
                MediaType.APPLICATION_JSON_TYPE, response.getMediaType());
    }

    public static void assertSuccessfulDeleteUserRequest(final Response response) {
        assertEquals("Status code should be 202",
                Response.Status.ACCEPTED.getStatusCode(), response.getStatus());
        assertEquals("Media type should be application/json",
                MediaType.APPLICATION_JSON_TYPE, response.getMediaType());
    }
}
