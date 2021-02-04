package severeone.oidc.auth.db.users;

public class NoSuchUserTypeException extends UserException {
	public NoSuchUserTypeException(String description) {
		super(String.format("No such user type exists: %s.", description));
	}
}
