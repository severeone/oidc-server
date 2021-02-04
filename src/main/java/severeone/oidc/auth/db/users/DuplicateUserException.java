package severeone.oidc.auth.db.users;

public class DuplicateUserException extends UserException {
	public DuplicateUserException(String description) {
		super(String.format("Duplicate user: %s.", description));
	}
}
