package severeone.oidc.auth.db.sessions;

public class IncompleteTokensRecordException extends SessionException {
	public IncompleteTokensRecordException(String description) {
		super(String.format("No enough data in tokens record for operation: %s.", description));
	}
}
