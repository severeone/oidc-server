package severeone.oidc.auth.resources.util;

import severeone.oidc.auth.core.User;
import severeone.oidc.auth.core.storage.AuthStorage;
import severeone.oidc.auth.db.users.UserException;

import javax.ws.rs.client.Entity;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import java.util.Map;

import static severeone.oidc.auth.resources.AuthService.*;
import static severeone.oidc.auth.resources.AuthServiceTest.*;
import static severeone.oidc.auth.util.resources.AuthJerseyViolationExceptionMapper.ERROR;
import static severeone.oidc.auth.util.resources.AuthJerseyViolationExceptionMapper.INVALID_REQUEST;
import static severeone.oidc.auth.util.resources.process.MigrateProcessor.*;

import static org.junit.Assert.*;

public class MigrateUserTestUtilities {

    public static Response migrateRequest(final String email, final String firstName, final String lastName) {
        Form form = new Form();
        if (email != null)
            form.param(EMAIL, email);
        if (firstName != null)
            form.param(FIRST_NAME, firstName);
        if (lastName != null)
            form.param(LAST_NAME, lastName);
        return RESOURCES.target(MIGRATE_USER_ENDPOINT).request().post(Entity.form(form));
    }

    public static void assertBadMigrateRequest(final Response response) {
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

    public static String assertSuccessfulMigrateRequest(final Response response, final AuthStorage authStorage) {
        assertTrue("Response should have entity", response.hasEntity());
        Map<String, String> entity = response.readEntity(Map.class);

        assertTrue("Response should have user_id body json parameter", entity.containsKey(USER_ID));
        final int userId = Integer.parseInt(entity.get(USER_ID));
        assertTrue("User ID should be a valid integer", userId > 0);

        User u = null;
        try {
            u = authStorage.loadUser(userId);
        } catch (UserException e) {
            fail("Failed to load a user");
        }
        assertNotNull("User ID should be valid", u);

        assertTrue("Response should have reset_code body json parameter", entity.containsKey(PASSWORD_RESET_CODE));
        final String resetCode = entity.get(PASSWORD_RESET_CODE);
        assertTrue("Reset code should be not empty", !resetCode.isEmpty());

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

        return resetCode;
    }
}
