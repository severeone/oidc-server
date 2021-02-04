package severeone.oidc.auth.db.sessions;

public class IncompleteSessionException extends SessionException {
	public IncompleteSessionException(String description) {
		super(String.format("No enough data in session for operation: %s.", description));
	}
}
