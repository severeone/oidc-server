package severeone.oidc.auth.util.resources.process;

import severeone.oidc.auth.AuthConfig;
import severeone.oidc.auth.core.User;
import severeone.oidc.auth.core.email.EmailServicesExtensionImpl;
import severeone.oidc.auth.core.storage.AuthStorage;
import severeone.oidc.auth.db.users.UserException;
import severeone.oidc.auth.util.Utilities;
import severeone.oidc.auth.util.resources.AuthJerseyViolationException;
import severeone.oidc.auth.util.resources.AuthJerseyViolationExceptionMapper;
import severeone.email.EmailService;

import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import java.util.HashMap;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.function.BiConsumer;

import static severeone.oidc.auth.resources.AuthService.*;

public class SignupProcessor extends RequestProcessor {

    private final static String EMAIL_VERIFICATION_LINK_TAG = "{{action_url}}";

    private String email;
    private String password;
    private String firstName;
    private String lastName;

    public SignupProcessor(final AuthConfig config, final AuthStorage authStorage) {
        super(config, authStorage);
    }

    public SignupProcessor userParams(final String email, final String password, final String firstName,
                                      final String lastName) {
        this.email = email;
        this.password = password;
        this.firstName = firstName;
        this.lastName = lastName;
        return this;
    }

    @Override
    public Response process() {
        validateSignupParameters();
//        sendVerificationEmail();
        createNewUser();
        return successfulSignupResponse();
    }

    private Response successfulSignupResponse() {
        return Response
                .status(Response.Status.CREATED)
                .header("Cache-Control", "no-store")
                .header("Pragma", "no-cache")
                .type(MediaType.APPLICATION_JSON)
                .entity(new HashMap<String, Object>() {{
                    put(SCOPE, OPENID);
                    put(RESPONSE_TYPE, AUTHORIZATION_CODE);
                    put(CLIENT_ID, CASE_BACKEND_CLIENT_ID);
                    put(REDIRECT_URI, config.getSignupCompletePage());
                }})
                .build();
    }

    private void validateSignupParameters() {
        // Validate email
        if (email == null || email.isEmpty())
            throw new AuthJerseyViolationException(EMAIL, null,
                    AuthJerseyViolationExceptionMapper.INVALID_REQUEST, "is empty");

        // Validate password
        if (password == null || password.isEmpty())
            throw new AuthJerseyViolationException(PASSWORD, null,
                    AuthJerseyViolationExceptionMapper.INVALID_REQUEST, "is empty");
    }

    private String createVerificationEmail() {
        final String verificationCode = UUID.randomUUID().toString();

        try {
            authStorage.saveEmailVerificationCode(email, verificationCode);
        } catch (UserException e) {
            throw new InternalServerErrorException("Failed to save email verification code");
        }

        String emailHtml = Utilities.getVerificationEmail(config.getVerificationEmailFilePath());
        return emailHtml.replace(EMAIL_VERIFICATION_LINK_TAG, config.getConfirmEmailPage() + verificationCode);
    }

    private void createNewUser() {
        User u;
        try {
            u = authStorage.saveUser(DEFAULT_USER_TYPE, email, password, firstName, lastName);
        } catch (UserException e) {
            // TODO: Log an error
            throw new InternalServerErrorException("Failed to create a new user");
        }

        if (u == null)
            throw new AuthJerseyViolationException(EMAIL, null,
                    AuthJerseyViolationExceptionMapper.INVALID_REQUEST, "is registered");
    }

    private void sendVerificationEmail() {
        EmailService srv = new EmailService(new EmailServicesExtensionImpl());

        // Check email first
        int result = 0;
        try {
            result = srv.checkEmailExists(email).get();
        } catch (InterruptedException | ExecutionException e) {
            throw new InternalServerErrorException("Failed to check the existence of an email " + email);
        }

        if (result > 0) {
            BiConsumer<Integer, Throwable> consumer = (res, ex) -> {
                if (res <= 0 || ex != null) {
                    throw new AuthJerseyViolationException(EMAIL, null,
                            AuthJerseyViolationExceptionMapper.INVALID_REQUEST, "does not exist");
                }
            };
            CompletableFuture<Integer> sendingEmail = srv.sendEmail(
                    email, "Case Medical Research: Registration complete!", "Case", createVerificationEmail(), true);
            sendingEmail.whenComplete(consumer);
        }
    }
}
