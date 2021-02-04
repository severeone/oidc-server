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

import java.util.HashMap;
import java.util.UUID;

import static severeone.oidc.auth.resources.AuthService.*;

public class MigrateProcessor extends RequestProcessor {

    public final static String USER_ID = "user_id";
    public final static String PASSWORD_RESET_CODE = "reset_code";

    private String email;
    private String firstName;
    private String lastName;

    public MigrateProcessor(final AuthConfig config, final AuthStorage authStorage) {
        super(config, authStorage);
    }

    public MigrateProcessor userParams(final String email, final String firstName, final String lastName) {
        this.email = email;
        this.firstName = firstName;
        this.lastName = lastName;
        return this;
    }

    @Override
    public Response process() {
        validateParameters();
        User user = createNewUser();
        String resetCode = getResetCode();
        return successfulMigrateResponse(user, resetCode);
    }

    private Response successfulMigrateResponse(final User user, final String resetCode) {
        return Response
                .status(Response.Status.CREATED)
                .header("Cache-Control", "no-store")
                .header("Pragma", "no-cache")
                .type(MediaType.APPLICATION_JSON)
                .entity(new HashMap<String, String>() {{
                    put(USER_ID, Integer.toString(user.id));
                    put(PASSWORD_RESET_CODE, resetCode);
                }})
                .build();
    }

    private void validateParameters() {
        // Validate email
        if (email == null || email.isEmpty())
            throw new AuthJerseyViolationException(EMAIL, null,
                    AuthJerseyViolationExceptionMapper.INVALID_REQUEST, "is empty");
    }

    private User createNewUser() {
        User u;
        try {
            u = authStorage.saveUser(DEFAULT_USER_TYPE, email, UUID.randomUUID().toString(), firstName, lastName);
        } catch (UserException e) {
            // TODO: Log an error
            throw new InternalServerErrorException("Failed to create a new user");
        }

        if (u == null)
            throw new AuthJerseyViolationException(EMAIL, null,
                    AuthJerseyViolationExceptionMapper.INVALID_REQUEST, "is registered");

        return u;
    }

    private String getResetCode() {
        final String resetCode = UUID.randomUUID().toString();

        try {
            authStorage.saveEmailVerificationCode(email, resetCode);
        } catch (UserException e) {
            throw new InternalServerErrorException("Failed to save a password reset code");
        }

        return resetCode;
    }
}
