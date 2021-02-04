package severeone.oidc.auth.util.resources;

import io.dropwizard.auth.UnauthorizedHandler;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import java.util.HashMap;

public class AuthTokenUnauthorizedHandler implements UnauthorizedHandler {

    public static final String INVALID_CLIENT = "invalid_client";
    public static final String INVALID_TOKEN = "invalid_token";

    private static final String BEARER = "Bearer";
    private static final String BASIC = "Basic";

    @Override
    public Response buildResponse(String prefix, String realm) {
        if (BASIC.equals(prefix))
            return Response
                    .status(Response.Status.UNAUTHORIZED)
                    .type(MediaType.APPLICATION_JSON)
                    .header("Cache-Control", "no-store")
                    .header("Pragma", "no-cache")
                    .entity(new HashMap<String, String>() {{
                        put(AuthJerseyViolationExceptionMapper.ERROR, INVALID_CLIENT);
                    }})
                    .build();
        else if (BEARER.equals(prefix))
            return Response
                    .status(Response.Status.UNAUTHORIZED)
                    .type(MediaType.APPLICATION_JSON)
                    .header("WWW-Authenticate", String.format("error=\"%s\"", INVALID_TOKEN))
                    .build();
        else
            return Response
                    .status(Response.Status.INTERNAL_SERVER_ERROR)
                    .build();
    }
}
