package severeone.oidc.auth.db.sessions;

public class DuplicateTokenException extends SessionException {
	public DuplicateTokenException(String tokenType, String description) {
		super(String.format("Duplicate %s: %s.", tokenType, description));
	}
}
