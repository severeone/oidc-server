package severeone.oidc.auth.db.users;

public class NoSuchEmailVerificationCodeException extends UserException {
    public NoSuchEmailVerificationCodeException(String description) {
        super(String.format("No email associated with %s.", description));
    }
}
