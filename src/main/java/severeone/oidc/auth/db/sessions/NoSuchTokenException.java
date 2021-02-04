package severeone.oidc.auth.db.sessions;

public class NoSuchTokenException extends SessionException {
	public NoSuchTokenException(String description) {
		super(String.format("No tokens record associated with an access token %s.", description));
	}
}
