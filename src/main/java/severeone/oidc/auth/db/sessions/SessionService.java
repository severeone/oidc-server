package severeone.oidc.auth.db.sessions;

import severeone.oidc.auth.db.users.UserException;
import severeone.oidc.auth.core.*;

import java.net.URL;
import java.sql.Timestamp;

// SessionService is a backend service for creating and managing authorization sessions and tokens of the platform.
public interface SessionService {
	// createSession creates a new session with the given parameters.
	// createSession is idempotent - Repeated calls with the same Authorization Code will not
	// create new sessions. They will simply return the existing session, unmodified.
	// Throws an exception (NoSuchUserException) if no such user exists.
	// Throws an exception (NoSuchClientException) if no such client exists.
	// Throws an exception (IncompleteSessionException) if no Authorization Code or redirect URI specified.
	// Throws an exception (InvalidRedirectUriException) if there's no such redirect URI registered
	// for the client with the specified ID.
	Session createSession(String authorizationCode, String clientId, int userId, URL redirectUri, String nonce,
                          Timestamp validTill)
			throws SessionException, UserException;

	// getSession should return a session with the given Authorization Code.
	// Returns null if this session does not exist.
	Session getSession(String authorizationCode) throws SessionException;

	// deleteSession removes a session with the specified Authorization Code from the db.
	// Throws an exception (NoSuchSessionException) if no session exists with that Authorization Code.
	void deleteSession(String authorizationCode) throws SessionException;

	// getClient should return the client with the given id.
	// Returns null if this client does not exist.
	Client getClient(String id) throws SessionException;

	// getTokensLifeTime should return tokens life time for the specified pair of user type and client id.
	// Returns null if no record exists for the specified pair of parameters.
	// Throws an exception (NoSuchUserTypeException) if no such user type exists.
	// Throws an exception (NoSuchClientException) if no such client exists.
	TokensLifeTime getTokensLifeTime(UserType userType, String clientId) throws SessionException, UserException;

	// createTokensRecord creates a record with a pair of tokens (access and refresh ones) for the specified client.
	// Throws an exception (DuplicateTokenException) if there's a record with the specified tokens.
	// Throws an exception (NoSuchClientException) if no such client exists.
	// Throws an exception (IncompleteTokensRecordException) if some parameter is not specified.
	AccessData createTokensRecord(String refreshToken, String encryptedAccessToken, String clientId, int userId)
			throws SessionException;

	// getTokensRecord should return an access data for the given refresh token.
	// Returns null if there's no such refresh token.
	AccessData getTokensRecord(String refreshToken) throws SessionException;

	// deleteTokensRecord deletes a record with a specified encrypted access token.
	// Throws an exception (NoSuchTokenException) if no token exists.
	void deleteTokensRecord(String encryptedAccessToken) throws SessionException;
}
