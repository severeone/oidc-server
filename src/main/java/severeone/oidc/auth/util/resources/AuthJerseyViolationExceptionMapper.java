package severeone.oidc.auth.util.resources;

import severeone.oidc.auth.resources.AuthService;
import severeone.oidc.auth.util.Utilities;

import io.dropwizard.jersey.validation.JerseyViolationException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.*;
import javax.ws.rs.ext.ExceptionMapper;

import java.util.*;

public class AuthJerseyViolationExceptionMapper implements ExceptionMapper<JerseyViolationException> {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthJerseyViolationExceptionMapper.class);

    public static final String ERROR = "error";
    public static final String ERROR_DESCRIPTION = "error_description";
    public static final String UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type";
    public static final String INVALID_SCOPE = "invalid_scope";
    public static final String UNAUTHORIZED_CLIENT = "unauthorized_client";
    public static final String INVALID_REQUEST = "invalid_request";
    public static final String UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type";
    public static final String INVALID_GRANT = "invalid_grant";

    @Context
    private ResourceInfo resourceInfo;

    @Context
    private UriInfo uriInfo;

    @Override
    public Response toResponse(final JerseyViolationException exception) {

        switch (resourceInfo.getResourceMethod().getName()) {
            case "authorizeGet":
            case "authorizePost":
            case "signon":
                return toResponseAuthorize(exception);
            case "token":
            case "signup":
            case "revoke":
            case "userinfoGet":
            case "userinfoPost":
            case "updateUser":
            case "resetPassword":
            case "setNewPassword":
            case "deleteUser":
            case "migrateUser":
            case "generateResetCode":
                return toResponseJson(exception);
        }
        return null;
    }

    private Response toResponseAuthorize(final JerseyViolationException exception) {
        if (!(exception instanceof AuthJerseyViolationException)) {
            return badAuthorizeRequestResponse(Utilities.getRootMessage(exception));
        }
        final AuthJerseyViolationException e = (AuthJerseyViolationException) exception;

        if (e.redirectUri == null)
            return badAuthorizeRequestResponse(e.errorCode + " " + e.parameterName + " " + e.errorDescription);

        return redirectURIResponse(getRedirectURI(e.redirectUri), e.errorCode,
                e.parameterName + " " + e.errorDescription, e.state);
    }

    private Response toResponseJson(final JerseyViolationException exception) {
        if (!(exception instanceof AuthJerseyViolationException)) {
            return badJsonRequestResponse(INVALID_REQUEST, Utilities.getRootMessage(exception));
        }
        final AuthJerseyViolationException e = (AuthJerseyViolationException) exception;
        return badJsonRequestResponse(e.errorCode, e.parameterName + " " + e.errorDescription);
    }

    private Response badJsonRequestResponse(final String error, final String description) {
        LOGGER.error("BadJsonRequestResponse error: " + error + ", description: " + description);

        return Response
                .status(Response.Status.BAD_REQUEST)
                .header("Cache-Control", "no-store")
                .header("Pragma", "no-cache")
                .type(MediaType.APPLICATION_JSON)
                .entity(new HashMap<String, String>() {{
                    put(ERROR, error);
                    put(ERROR_DESCRIPTION, description);
                }})
                .build();
    }

    private Response badAuthorizeRequestResponse(String errmsg) {
        LOGGER.error("BadAuthorizeRequestResponse error: " + errmsg);
        return Response
                .status(Response.Status.BAD_REQUEST)
//                .type(MediaType.APPLICATION_FORM_URLENCODED)
                .entity(errmsg)
                .build();
    }

    private Response redirectURIResponse(UriBuilder redirectUri, final String error,
                                         final String description, final String state) {
        LOGGER.error("RedirectURIResponse error: " + error + ", description: " + description + ", state: " + state);
        final String escapedDescription = Utilities.escape(description);

        UriBuilder resRedirectUri = redirectUri.queryParam(ERROR, error);
        if (escapedDescription != null)
            resRedirectUri = resRedirectUri.queryParam(ERROR_DESCRIPTION, escapedDescription);
        if (state != null && !state.isEmpty())
            resRedirectUri = resRedirectUri.queryParam(AuthService.STATE, state);

        return Response
                .status(Response.Status.FOUND)
                .location(resRedirectUri.build())
//                .type(MediaType.APPLICATION_FORM_URLENCODED)
                .build();
    }

    private static UriBuilder getRedirectURI(final String redirectUri) {
        return UriBuilder.fromUri(redirectUri);
    }
}
