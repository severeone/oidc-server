package severeone.oidc.auth.db.sessions;

public class NoSuchSessionException extends SessionException {
	public NoSuchSessionException(String description) {
		super(String.format("No session associated with %s.", description));
	}
}