package severeone.oidc.auth.util.resources;

import severeone.oidc.auth.util.Utilities;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.*;
import javax.ws.rs.ext.ExceptionMapper;

public class AuthInternalServerErrorExceptionMapper implements ExceptionMapper<InternalServerErrorException> {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthInternalServerErrorExceptionMapper.class);
    @Context
    private ResourceInfo resourceInfo;

    @Override
    public Response toResponse(InternalServerErrorException exception) {
        String msg = "Exception in method " + resourceInfo.getResourceMethod().getName() + ":" + Utilities.getRootMessage(exception);
        LOGGER.error(msg);

        switch (resourceInfo.getResourceMethod().getName()) {
            case "authorizeGet":
            case "authorizePost":
            case "signon":
            case "setNewPassword":
            case "resetPassword":
            case "deleteUser":
                return Response
                        .status(Response.Status.INTERNAL_SERVER_ERROR)
//                        .type(MediaType.APPLICATION_FORM_URLENCODED)
//                        .entity(msg)
                        .build();

            case "token":
            case "signup":
            case "revoke":
            case "userinfoGet":
            case "userinfoPost":
            case "updateUser":
                return Response
                        .status(Response.Status.INTERNAL_SERVER_ERROR)
                        .header("Cache-Control", "no-store")
                        .header("Pragma", "no-cache")
//                        .type(MediaType.APPLICATION_JSON)
//                        .entity(msg)
                        .build();
        }
        return null;
    }
}