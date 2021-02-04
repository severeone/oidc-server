package severeone.oidc.auth.resources;


import severeone.oidc.auth.api.test.EmailTestResponse;
import severeone.email.EmailService;

import com.codahale.metrics.annotation.Metered;
import com.codahale.metrics.annotation.Timed;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

// TODO set admin permissions for access to this resource
@Path("/test/email")
@Produces(MediaType.APPLICATION_JSON)
public class TestResource {

    private static final Logger LOGGER = LoggerFactory.getLogger(TestResource.class);

    private final EmailService srv;

    public TestResource(EmailService srv) {
        this.srv = srv;
    }

    @POST
    @Path("/checkexists")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Timed(name = "get-requests-timed")
    @Metered(name = "get-requests-metered")
    public EmailTestResponse checkEmailExists(@FormParam("email") String email) throws Exception {
        LOGGER.info(String.format("Entering 'checkEmailExists': email=%s", email));
        return new EmailTestResponse(srv.checkEmailExists(email).get());
    }

    @POST
    @Path("/sendemail")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Timed(name = "get-requests-timed")
    @Metered(name = "get-requests-metered")
    public EmailTestResponse sendEmail(@FormParam("to") String to,
                             @FormParam("subject") String subject,
                             @FormParam("display_name") String displayName,
                             @FormParam("body") String body) throws Exception {
        LOGGER.info(String.format("Entering 'sendEmail': to=%s, subject=%s, display_name=%s, body=%s, ", to, subject, displayName, body));
        return new EmailTestResponse(srv.sendEmail(to, subject, displayName, body, false).get());
    }

    @PUT
    @Path("/reset_password")
    @Timed(name = "get-requests-timed")
    @Metered(name = "get-requests-metered")
    public Response resetPassword(@FormParam("email") String email,
                                  @FormParam("authcode") String code) {
        LOGGER.info(String.format("Entering 'resetPassword': email=%s, authcode=%s, ", email, code));
        return Response.ok().build();
    }
}
