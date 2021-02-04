package severeone.oidc.auth.resources.util;

import severeone.oidc.auth.core.User;

import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import java.util.Map;

import static severeone.oidc.auth.resources.AuthService.*;
import static severeone.oidc.auth.resources.AuthServiceTest.*;

import static org.junit.Assert.*;

public class UserInfoTestUtilities {

    public static Response userInfoRequest(RequestMethod method, final String accessToken) {
        Invocation.Builder b = RESOURCES.target(USERINFO_ENDPOINT).request();
        if (accessToken != null)
            b = b.header(AUTHORIZATION_HEADER, getBearerAuthorizationHeader(accessToken));
        if (method == RequestMethod.GET)
            return b.get();
        else
            return b.post(Entity.form(new Form()));
    }

    public static void assertUnauthorizedUserInfoRequest(final Response response) {
        assertNotNull(WWW_AUTHENTICATE_HEADER + " header should present",
                response.getHeaderString(WWW_AUTHENTICATE_HEADER));
        final String error = "error=\"invalid_token\"";
        assertEquals(WWW_AUTHENTICATE_HEADER + " header should be " + error,
                error, response.getHeaderString(WWW_AUTHENTICATE_HEADER));

        assertEquals("Status code should be 401",
                Response.Status.UNAUTHORIZED.getStatusCode(), response.getStatus());
    }

    public static void assertSuccessfulUserInfoRequest(final Response response, final User user) {
        assertTrue("Response should have entity", response.hasEntity());
        Map<String, String> entity = response.readEntity(Map.class);

        assertUserClaim(entity, user.email, EMAIL);
        assertUserClaim(entity, user.firstName, FIRST_NAME);
        assertUserClaim(entity, user.lastName, LAST_NAME);
        assertUserClaim(entity, user.type.name(), USER_TYPE);
        assertUserClaim(entity, CASE_OP, OPENID_PROVIDER_ORIGIN);

        assertEquals("Status code should be 200",
                Response.Status.OK.getStatusCode(), response.getStatus());
        assertEquals("Media type should be application/json",
                MediaType.APPLICATION_JSON_TYPE, response.getMediaType());
    }

    private static void assertUserClaim(final Map<String, String> entity, final String expected, final String actualKey) {
        assertTrue("Response should have " + actualKey + " body json parameter", entity.containsKey(actualKey));
        assertEquals("Token type should be " + expected, expected, entity.get(actualKey));
    }
}
