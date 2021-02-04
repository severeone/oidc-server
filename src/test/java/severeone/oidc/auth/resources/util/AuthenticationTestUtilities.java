package severeone.oidc.auth.resources.util;

import severeone.oidc.auth.core.Session;
import severeone.oidc.auth.db.sessions.SessionException;

import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import java.net.URI;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static severeone.oidc.auth.resources.AuthService.*;
import static severeone.oidc.auth.resources.AuthService.REDIRECT_URI;
import static severeone.oidc.auth.resources.AuthServiceTest.*;
import static severeone.oidc.auth.util.resources.AuthJerseyViolationExceptionMapper.ERROR;
import static org.junit.Assert.*;
import static org.junit.Assert.assertFalse;

public class AuthenticationTestUtilities {

    public static Response authRequest(final String endpoint, RequestMethod method, final String[][] params) {
        if (RequestMethod.GET.equals(method)) {
            WebTarget target = RESOURCES.target(endpoint);
            for (final String[] p : params) {
                target = target.queryParam(p[0], p[1]);
            }
            return target.request().get();
        } else if (RequestMethod.POST.equals(method)) {
            Form form = new Form();
            for (final String[] p : params) {
                form = form.param(p[0], p[1]);
            }
            return RESOURCES.target(endpoint).request().post(Entity.form(form));
        }
        fail("Unknown authRequest method");
        return Response.ok().build();
    }

    public static void assertBadAuthorizeRequest(final Response response) {
        assertEquals("Status code should be 400",
                Response.Status.BAD_REQUEST.getStatusCode(), response.getStatus());
        assertEquals("Media type should be application/x-www-form-urlencoded",
                MediaType.APPLICATION_FORM_URLENCODED_TYPE, response.getMediaType());
    }

    public static void assertErrorRedirectAuthorizeRequest(final Response response, final String errorCode,
                                                           final Map<String, String> responseParams,
                                                           final String state) {
        assertTrue("Redirect uri should have error query parameter", responseParams.containsKey(ERROR));
        assertEquals("Error code should be " + errorCode, errorCode, responseParams.get(ERROR));

        if (state != null) {
            assertTrue("Redirect uri should have state query parameter", responseParams.containsKey(STATE));
            assertEquals("State should be " + state, state, responseParams.get(STATE));
        }

        assertEquals("Status code should be 404 (because of the redirection)",
                Response.Status.NOT_FOUND.getStatusCode(), response.getStatus());
        // TODO: Find out why the actual media type is application/json. This is totally wrong.
//        assertEquals("Media type should be application/x-www-form-urlencoded",
//                MediaType.APPLICATION_FORM_URLENCODED_TYPE, response.getMediaType());
    }

    public static void assertSuccessfulRedirectAuthorizeRequest(final Response response,
                                                                final Map<String, String> responseParams,
                                                                final Map<String, String> params) {
        assertTrue("Redirect uri should have code query parameter",
                responseParams.containsKey(AUTHORIZATION_CODE));
        assertTrue("Authorization code should be not empty",
                !responseParams.get(AUTHORIZATION_CODE).isEmpty());

        final String state = params.get(STATE);
        if (state != null) {
            assertTrue("Redirect uri should have state query parameter", responseParams.containsKey(STATE));
            assertEquals("State should be " + state, state, responseParams.get(STATE));
        }

        assertEquals("Status code should be 404 (because of the redirection)",
                Response.Status.NOT_FOUND.getStatusCode(), response.getStatus());
        // TODO: Find out why the actual media type is application/json. This is totally wrong.
//        assertEquals("Media type should be application/x-www-form-urlencoded",
//                MediaType.APPLICATION_FORM_URLENCODED_TYPE, response.getMetadata());

        Session s = null;
        try {
            s = AUTH_STORAGE.loadAuthorizationData(responseParams.get(AUTHORIZATION_CODE));
        } catch (SessionException e) {
            fail("Failed to load auth data");
        }
        assertNotNull(s);
        assertEquals("Auth data should contain a correct nonce", params.get(NONCE), s.nonce);
        assertEquals("Auth data should contain a correct auth code", responseParams.get(AUTHORIZATION_CODE),
                s.authorizationCode);
        assertEquals("Auth data should contain a correct client id", params.get(CLIENT_ID), s.clientId);
        assertEquals("Auth data should contain a correct user id", TEST_USER.id, s.userId);
        assertEquals("Auth data should contain a correct redirect uri", params.get(REDIRECT_URI),
                s.redirectUri.toString());
        assertFalse("Auth data should be not expired", s.isExpired());
    }

    public static void assertLoginRedirectAuthorizeRequest(final Response response,
                                                           final Map<String, String> responseParams,
                                                           final String[][] params) {
        final URI location = location(response);
        final String path = location.toString().split("\\?")[0];

        assertEquals("Redirect uri should be web login page", CONFIG.getLoginPage(), path);
        for (String[] param : params) {
            if (EMAIL.equals(param[0]) || PASSWORD.equals(param[0]) || ID_TOKEN_HINT.equals(param[0]))
                continue;
            assertTrue("Redirect uri should contain " + param[0], responseParams.containsKey(param[0]));
            assertEquals(param[0] + " should be equal to " + param[1],
                    responseParams.get(param[0]), param[1]);
        }

        assertEquals("Status code should be 404 (because of the redirection)",
                Response.Status.NOT_FOUND.getStatusCode(), response.getStatus());
        // TODO: Find out why the actual media type is application/json. This is totally wrong.
//        assertEquals("Media type should be application/x-www-form-urlencoded",
//                MediaType.APPLICATION_FORM_URLENCODED_TYPE, response.getMediaType());
    }

    public static URI location(final Response response) {
        Pattern uriPattern = Pattern.compile("uri=([^\\s]*),");
        Matcher m = uriPattern.matcher(response.toString());
        if (m.find()) {
            return URI.create(m.group(1));
        }
        return null;
    }
}
