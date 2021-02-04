package severeone.oidc.auth.db.users;

public class IncompleteUserException extends UserException {
	public IncompleteUserException(String description) {
		super(String.format("No enough data in user for operation: %s.", description));
	}
}
