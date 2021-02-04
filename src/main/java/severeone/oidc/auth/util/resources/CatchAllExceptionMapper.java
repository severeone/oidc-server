package severeone.oidc.auth.util.resources;

import severeone.oidc.auth.util.Utilities;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Providers;

import java.lang.reflect.Method;

public class CatchAllExceptionMapper implements ExceptionMapper<Throwable> {

    private static final Logger LOGGER = LoggerFactory.getLogger(CatchAllExceptionMapper.class);

    @Context
    private ResourceInfo resourceInfo;

    @Context
    private Providers providers;

    @Override
    public Response toResponse(Throwable exception) {
        Method m = resourceInfo.getResourceMethod();
        String msg = "Exception in method " + (m != null ? m.getName() : "[no method yet]") + ": " + Utilities.getRootMessage(exception);
        LOGGER.error(msg);

        ExceptionMapper mapper = providers.getExceptionMapper(exception.getClass());
        if (mapper != null) {
            return mapper.toResponse(exception);
        } else {
            return Response
                    .status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(msg)
                    .build();
        }
    }
}
