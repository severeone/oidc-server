package severeone.oidc.auth.db.sessions;

public class SessionException extends Exception {
	public SessionException(String errorMessage) {
		super(errorMessage);
	}
}
