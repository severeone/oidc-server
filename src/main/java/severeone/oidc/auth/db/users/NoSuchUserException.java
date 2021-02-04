package severeone.oidc.auth.db.users;

public class NoSuchUserException extends UserException {
	public NoSuchUserException(String description) {
		super(String.format("No user associated with %s.", description));
	}
}
