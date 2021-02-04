package severeone.oidc.auth.db.sessions;

public class NoSuchClientException extends SessionException {
	public NoSuchClientException(String description) {
		super(String.format("No client associated with %s.", description));
	}
}
