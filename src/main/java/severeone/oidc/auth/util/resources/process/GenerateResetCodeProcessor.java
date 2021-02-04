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

import static severeone.oidc.auth.resources.AuthService.EMAIL;

public class GenerateResetCodeProcessor extends RequestProcessor {

    public final static String PASSWORD_RESET_CODE = "reset_code";
    public final static String IS_PASSWORD_SET = "is_password_set";
    public final static String USER_ID = "user_id";

    private String email;
    private User user;

    public GenerateResetCodeProcessor(final AuthConfig config, final AuthStorage authStorage) {
        super(config, authStorage);
    }

    public GenerateResetCodeProcessor email(final String email) {
        this.email = email;
        return this;
    }

    @Override
    public Response process() {
        validateParameters();
        String resetCode = getResetCode();
        return successfulGenerateResetCodeResponse(resetCode);
    }

    private Response successfulGenerateResetCodeResponse(final String resetCode) {
        return Response
                .status(Response.Status.CREATED)
                .header("Cache-Control", "no-store")
                .header("Pragma", "no-cache")
                .type(MediaType.APPLICATION_JSON)
                .entity(new HashMap<String, Object>() {{
                    put(PASSWORD_RESET_CODE, resetCode);
                    put(IS_PASSWORD_SET, !(user.passwordHash == null || user.passwordHash.isEmpty()));
                    put(USER_ID, Integer.toString(user.id));
                }})
                .build();
    }

    private void validateParameters() {
        // Validate email
        if (email == null || email.isEmpty())
            throw new AuthJerseyViolationException(EMAIL, null,
                    AuthJerseyViolationExceptionMapper.INVALID_REQUEST, "is empty");

        try {
            user = authStorage.loadUser(email);
        } catch (UserException e) {
            // TODO: Log an error
            throw new InternalServerErrorException("Failed to load a user by email");
        }

        if (user == null)
            throw new AuthJerseyViolationException(EMAIL, null,
                    AuthJerseyViolationExceptionMapper.INVALID_REQUEST, "is not registered");
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
