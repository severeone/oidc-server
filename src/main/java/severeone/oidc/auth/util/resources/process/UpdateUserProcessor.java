package severeone.oidc.auth.util.resources.process;

import severeone.oidc.auth.AuthConfig;
import severeone.oidc.auth.core.UpdateUserJson;
import severeone.oidc.auth.core.User;
import severeone.oidc.auth.core.UserType;
import severeone.oidc.auth.core.storage.AuthStorage;
import severeone.oidc.auth.db.users.DuplicateUserException;
import severeone.oidc.auth.db.users.IncompleteUserException;
import severeone.oidc.auth.db.users.UserException;
import severeone.oidc.auth.tokens.IDToken;
import severeone.oidc.auth.tokens.util.InvalidIDToken;
import severeone.oidc.auth.tokens.util.InvalidIDTokenKey;
import severeone.oidc.auth.util.Utilities;
import severeone.oidc.auth.util.resources.AuthJerseyViolationException;
import severeone.oidc.auth.util.resources.AuthJerseyViolationExceptionMapper;

import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import static severeone.oidc.auth.resources.AuthService.ID_TOKEN;
import static severeone.oidc.auth.resources.AuthService.PASSWORD;

public class UpdateUserProcessor extends RequestProcessor {

    private UpdateUserJson json;
    private String clientId;
    private IDToken idToken;

    public UpdateUserProcessor(final AuthConfig config, final AuthStorage storage) {
        super(config, storage);
    }

    public UpdateUserProcessor updateUserJson(UpdateUserJson json) {
        this.json = json;
        return this;
    }

    public UpdateUserProcessor clientId(final String clientId) {
        this.clientId = clientId;
        return this;
    }

    @Override
    public Response process() {
        if (json == null)
            throw new AuthJerseyViolationException("User data", null,
                    AuthJerseyViolationExceptionMapper.INVALID_REQUEST, "is missing");

        validateIDToken();
        final User user = validateUserPassword();
        updateUserProfile(user);

        return Response
                .status(Response.Status.ACCEPTED)
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }

    private void validateIDToken() {
        final String signedIDToken = json.getSignedIDToken();

        if (signedIDToken == null)
            throw new AuthJerseyViolationException(ID_TOKEN, null,
                    AuthJerseyViolationExceptionMapper.INVALID_GRANT, "is missing");

        try {
            idToken = IDToken.readFromString(signedIDToken,
                    Utilities.getToken(config.getIdTokenKeyFilePath()));
        } catch (InvalidIDTokenKey e) {
            // TODO: Log an error
            throw new InternalServerErrorException("Failed to apply the ID token key");
        } catch (InvalidIDToken e) {
            throw new AuthJerseyViolationException(ID_TOKEN, null,
                    AuthJerseyViolationExceptionMapper.INVALID_GRANT, "is corrupted");
        }

        if (!idToken.isValid(clientId)) {
            throw new AuthJerseyViolationException(ID_TOKEN, null,
                    AuthJerseyViolationExceptionMapper.INVALID_GRANT, "is not valid");
        }
    }

    private User validateUserPassword() {
        if (json.getUser() == null)
            throw new AuthJerseyViolationException("User data", null,
                    AuthJerseyViolationExceptionMapper.INVALID_REQUEST, "is not provided");

        final String password = json.getUser().getPassword();

        User u;
        try {
            u = authStorage.loadUser(Integer.parseInt(idToken.getUserId()));
        } catch (UserException e) {
            throw new InternalServerErrorException("Failed to load user profile");
        }
        if (u == null)
            throw new InternalServerErrorException("Failed to load user profile");

        if (!Utilities.verifyHash(password, u.passwordHash))
            throw new AuthJerseyViolationException(PASSWORD, null,
                    AuthJerseyViolationExceptionMapper.INVALID_GRANT, "is not valid");

        return u;
    }

    private void updateUserProfile(final User user) {
        final String email = json.getUser().getEmail() != null ? json.getUser().getEmail() : user.email;
        final String firstName = json.getUser().getFirstName() != null ? json.getUser().getFirstName() : user.firstName;
        final String lastName = json.getUser().getLastName() != null ? json.getUser().getLastName() : user.lastName;
        final String password = json.getUser().getNewPassword();
        final UserType userType = user.type;

        try {
            authStorage.updateUser(user.id, email, firstName, lastName, password, userType);
        } catch (IncompleteUserException e) {
            throw new AuthJerseyViolationException("User", null,
                    AuthJerseyViolationExceptionMapper.INVALID_REQUEST, e.getMessage());
        } catch (DuplicateUserException e) {
            throw new AuthJerseyViolationException("User", null,
                    AuthJerseyViolationExceptionMapper.INVALID_REQUEST, "This email is already registered");
        } catch (UserException e) {
            throw new InternalServerErrorException("Failed to update user");
        }
    }
}
