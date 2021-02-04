package severeone.oidc.auth.util.resources.process;

import severeone.oidc.auth.AuthConfig;
import severeone.oidc.auth.core.User;
import severeone.oidc.auth.core.storage.AuthStorage;
import severeone.oidc.auth.db.users.UserException;
import severeone.oidc.auth.util.Utilities;
import severeone.oidc.auth.util.resources.AuthJerseyViolationException;
import severeone.oidc.auth.util.resources.AuthJerseyViolationExceptionMapper;

import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import static severeone.oidc.auth.resources.AuthService.*;

public class DeleteUserProcessor extends RequestProcessor {

    private String email;
    private String adminToken;

    public DeleteUserProcessor(final AuthConfig config, final AuthStorage storage) {
        super(config, storage);
    }

    public DeleteUserProcessor email(final String email) {
        this.email = email;
        return this;
    }

    public DeleteUserProcessor adminToken(final String adminToken) {
        this.adminToken = adminToken;
        return this;
    }

    @Override
    public Response process() {
        validateParameters();
        deleteUser();

        return Response
                .status(Response.Status.ACCEPTED)
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }

    private void validateParameters() {
        if (adminToken == null)
            throw new AuthJerseyViolationException(ADMIN_TOKEN, null,
                    AuthJerseyViolationExceptionMapper.INVALID_GRANT, "is missing");
        if (!adminToken.equals(Utilities.getToken(config.getAdminTokenFilePath())))
            throw new AuthJerseyViolationException(ADMIN_TOKEN, null,
                    AuthJerseyViolationExceptionMapper.INVALID_GRANT, "is not valid");

        if (email == null)
            throw new AuthJerseyViolationException(EMAIL, null,
                    AuthJerseyViolationExceptionMapper.INVALID_REQUEST, "is missing");
    }

    private void deleteUser() {
        User u;
        try {
            u = authStorage.loadUser(email);
        } catch (UserException e) {
            throw new InternalServerErrorException("Failed to load user profile");
        }
        if (u == null)
            throw new AuthJerseyViolationException(EMAIL, null,
                    AuthJerseyViolationExceptionMapper.INVALID_REQUEST, "is not registered");

        try {
            if (!authStorage.deleteUser(u.id))
                throw new InternalServerErrorException("Failed to delete a user profile");
        } catch (UserException e) {
            throw new InternalServerErrorException("Failed to delete a user profile");
        }
    }
}
