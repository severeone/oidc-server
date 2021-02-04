package severeone.oidc.auth.db.sessions;

public class InvalidRedirectUriException extends SessionException {
	public InvalidRedirectUriException(String description) {
		super(String.format("Redirect URI is not registered for a specified client: %s.", description));
	}
}
