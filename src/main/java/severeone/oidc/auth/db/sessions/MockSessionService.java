package severeone.oidc.auth.db.sessions;

import severeone.oidc.auth.db.users.MockUserService;
import severeone.oidc.auth.db.users.NoSuchUserException;
import severeone.oidc.auth.db.users.NoSuchUserTypeException;
import severeone.oidc.auth.db.users.UserException;
import severeone.oidc.auth.core.*;

import java.net.URL;
import java.sql.Timestamp;
import java.util.HashMap;
import java.util.Map;

public class MockSessionService implements SessionService {

	private Map<String, Client> clients = new HashMap<>();
	private Map<String, TokensLifeTime> tokensLifeTimes = new HashMap<>();
	private Map<String, Session> sessions = new HashMap<>();
	private Map<String, AccessData> accessDataByRefreshToken = new HashMap<>();
	private Map<String, AccessData> accessDataByEncryptedAccessToken = new HashMap<>();
	private MockUserService userService;

	public MockSessionService(MockUserService userService, Client testClient, TokensLifeTime testTokensLifeTime) {
		this.userService = userService;
		clients.put(testClient.id, testClient);
		tokensLifeTimes.put(getTokensLifeTimesKey(testTokensLifeTime), testTokensLifeTime);
	}

	private String getTokensLifeTimesKey(TokensLifeTime tokensLifeTime) {
		return tokensLifeTime.userType.toString() + tokensLifeTime.clientId;
	}

	private String getTokensLifeTimesKey(UserType userType, String clientId) {
		return userType.toString() + clientId;
	}

	@Override
	public Session createSession(String authorizationCode, String clientId, int userId, URL redirectUri,
	                             String nonce, Timestamp validTill) throws SessionException, UserException {
		Session s = getSession(authorizationCode);
		if (s != null)
			return new Session(s);

		User u = null;
		try {
			u = userService.getUserById(userId);
		} catch (UserException e) {
			// whatever
		}
		if (u == null)
			throw new NoSuchUserException(String.valueOf(userId));

		Client c = getClient(clientId);
		if (c == null)
			throw new NoSuchClientException(clientId);

		if (authorizationCode.isEmpty())
			throw new IncompleteSessionException("Authorization Code");
		if (redirectUri == null)
			throw new IncompleteSessionException("redirect URI");

		if (!c.containsRedirectUri(redirectUri))
			throw new InvalidRedirectUriException(clientId + " " + redirectUri.toString());

		s = new Session(authorizationCode, clientId, userId, validTill, redirectUri.toString(), nonce);
		sessions.put(authorizationCode, new Session(s));

		return s;
	}

	@Override
	public Session getSession(String authorizationCode) throws SessionException {
		if (!sessions.containsKey(authorizationCode))
			return null;
		return sessions.get(authorizationCode);
	}

	@Override
	public void deleteSession(String authorizationCode) throws SessionException {
		if (getSession(authorizationCode) == null)
			throw new NoSuchSessionException(authorizationCode);
		sessions.remove(authorizationCode);
	}

	@Override
	public Client getClient(String id) throws SessionException {
		if (!clients.containsKey(id))
			return null;
		return new Client(clients.get(id));
	}

	@Override
	public TokensLifeTime getTokensLifeTime(UserType userType, String clientId) throws SessionException, UserException {
		// Check if the given user type exists.
		if (userService.getUserType(userType) == null)
			throw new NoSuchUserTypeException(userType.toString());

		// Check if the given client id exists.
		if (getClient(clientId) == null)
			throw new NoSuchClientException(clientId);

		if (!tokensLifeTimes.containsKey(getTokensLifeTimesKey(userType, clientId)))
			return null;
		return tokensLifeTimes.get(getTokensLifeTimesKey(userType, clientId));
	}

	@Override
	public AccessData createTokensRecord(String refreshToken, String encryptedAccessToken, String clientId, int userId)
			throws SessionException {
		AccessData ad = getTokensRecord(refreshToken);
		if (ad != null)
			throw new DuplicateTokenException("refresh token", refreshToken);

		ad = getTokensRecordByEncryptedAccessToken(encryptedAccessToken);
		if (ad != null)
			throw new DuplicateTokenException("encrypted access token", encryptedAccessToken);

		if (getClient(clientId) == null)
			throw new NoSuchClientException(clientId);

		if (refreshToken.isEmpty())
			throw new IncompleteTokensRecordException("refresh token");
		if (encryptedAccessToken.isEmpty())
			throw new IncompleteTokensRecordException("encrypted access token");

		ad = new AccessData(refreshToken, encryptedAccessToken, clientId, userId);
		accessDataByRefreshToken.put(refreshToken, new AccessData(ad));
		accessDataByEncryptedAccessToken.put(encryptedAccessToken, new AccessData(ad));

		return ad;
	}

	@Override
	public AccessData getTokensRecord(String refreshToken) throws SessionException {
		if (!accessDataByRefreshToken.containsKey(refreshToken))
			return null;
		return accessDataByRefreshToken.get(refreshToken);
	}

	@Override
	public void deleteTokensRecord(String encryptedAccessToken) throws SessionException {
		AccessData ad = getTokensRecordByEncryptedAccessToken(encryptedAccessToken);
		if (ad == null)
			throw new NoSuchTokenException(encryptedAccessToken);
		accessDataByEncryptedAccessToken.remove(encryptedAccessToken);
		accessDataByRefreshToken.remove(ad.refreshToken);
	}

	private AccessData getTokensRecordByEncryptedAccessToken(String encryptedAccessToken) {
		if (!accessDataByEncryptedAccessToken.containsKey(encryptedAccessToken))
			return null;
		return accessDataByEncryptedAccessToken.get(encryptedAccessToken);
	}
}
