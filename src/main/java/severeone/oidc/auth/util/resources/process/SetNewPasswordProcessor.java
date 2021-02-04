package severeone.oidc.auth.util.resources.process;

import severeone.oidc.auth.AuthConfig;
import severeone.oidc.auth.core.User;
import severeone.oidc.auth.core.storage.AuthStorage;
import severeone.oidc.auth.db.users.UserException;
import severeone.oidc.auth.util.resources.AuthJerseyViolationException;
import severeone.oidc.auth.util.resources.AuthJerseyViolationExceptionMapper;

import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import static severeone.oidc.auth.resources.AuthService.CONFIRMATION_CODE;
import static severeone.oidc.auth.resources.AuthService.PASSWORD;

public class SetNewPasswordProcessor extends RequestProcessor {

    private String code;
    private String password;

    public SetNewPasswordProcessor(final AuthConfig config, final AuthStorage authStorage) {
        super(config, authStorage);
    }

    public SetNewPasswordProcessor code(final String code) {
        this.code = code;
        return this;
    }

    public SetNewPasswordProcessor password(final String password) {
        this.password = password;
        return this;
    }

    @Override
    public Response process() {
        String email;
        try {
            email = authStorage.verifyEmailByCode(code);
            if (email == null)
                throw new AuthJerseyViolationException(CONFIRMATION_CODE, null,
                        AuthJerseyViolationExceptionMapper.INVALID_GRANT, "is not registered");
        } catch (UserException e) {
            throw new InternalServerErrorException("Failed to verify email by code: " + code);
        }

        setNewPassword(email);

        return Response.ok().type(MediaType.APPLICATION_JSON).build();
    }

    private void setNewPassword(final String email) {
        User u;
        try {
            u = authStorage.loadUser(email);
        } catch (UserException e) {
            throw new InternalServerErrorException("Failed to load user by email: " + email);
        }
        if (u == null)
            throw new InternalServerErrorException("Failed to load user by email: " + email);

        try {
            authStorage.updateUser(u.id, u.email, u.firstName, u.lastName, password, u.type);
        } catch (UserException e) {
            throw new InternalServerErrorException("Failed to set a new password for a user: " + email);
        }
    }
}
