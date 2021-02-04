package severeone.oidc.auth.core.storage;

import severeone.oidc.auth.core.*;
import severeone.oidc.auth.db.sessions.*;
import severeone.oidc.auth.db.users.NoSuchUserException;
import severeone.oidc.auth.db.users.NoSuchUserTypeException;
import severeone.oidc.auth.db.users.UserException;
import severeone.oidc.auth.db.users.UserService;

import java.net.URL;
import java.sql.Timestamp;

public class DbAuthStorage implements AuthStorage {

	private final SessionService sessionService;
	private final UserService userService;

	public DbAuthStorage(final SessionService sessionService, final UserService userService) {
		this.sessionService = sessionService;
		this.userService = userService;
	}

	@Override
	public Session saveAuthorizationData(String authorizationCode, String clientId, int userId, URL redirectUri,
                                         String nonce, Timestamp validTill) throws UserException, SessionException {
		return sessionService.createSession(authorizationCode, clientId, userId, redirectUri, nonce, validTill);
	}

	@Override
	public Session loadAuthorizationData(String authorizationCode) throws SessionException {
		return sessionService.getSession(authorizationCode);
	}

	@Override
	public boolean removeAuthorizationData(String authorizationCode) throws SessionException {
		try {
			sessionService.deleteSession(authorizationCode);
		} catch (NoSuchSessionException e) {
			return false;
		}
		return true;
	}

	@Override
	public AccessData saveAccessData(String refreshToken, String encryptedAccessToken, String clientId, int userId)
			throws SessionException {
		return sessionService.createTokensRecord(refreshToken, encryptedAccessToken, clientId, userId);
	}

	@Override
	public AccessData loadAccessData(String refreshToken) throws SessionException {
		return sessionService.getTokensRecord(refreshToken);
	}

	@Override
	public boolean removeAccessData(String encryptedAccessToken) throws SessionException {
		try {
			sessionService.deleteTokensRecord(encryptedAccessToken);
		} catch (NoSuchTokenException e) {
			return false;
		}
		return true;
	}

	@Override
	public TokensLifeTime loadTokensLifeTime(UserType userType, String clientId)
			throws SessionException, UserException {
		TokensLifeTime tlt;
		try {
			tlt = sessionService.getTokensLifeTime(userType, clientId);
		} catch (NoSuchClientException | NoSuchUserTypeException e) {
			return null;
		}
		return tlt;
	}

	@Override
	public Client loadClient(String clientId) throws SessionException {
		Client c;
		try {
			c = sessionService.getClient(clientId);
		} catch (NoSuchClientException e) {
			return null;
		}
		return c;
	}

	@Override
	public User loadUser(String email) throws UserException {
		return userService.getUserByEmail(email);
	}

	@Override
	public User loadUser(int id) throws UserException {
		return userService.getUserById(id);
	}

	@Override
	public User saveUser(UserType userType, String email, String password, String firstName, String lastName)
			throws UserException {
		return userService.createUser(userType, email, password, firstName, lastName);
	}

	@Override
	public void updateUser(int id, String email, String firstName, String lastName, String password, UserType userType)
			throws UserException {
		userService.updateUserInfo(id, email, firstName, lastName);
		userService.updateUserType(id, userType);
		if (password != null)
			userService.setPassword(id, password);
	}

	@Override
	public boolean deleteUser(int id) throws UserException {
		try {
			userService.deleteUser(id);
		} catch (NoSuchUserException e) {
			return false;
		}
		return true;
	}

	@Override
	public void saveEmailVerificationCode(String email, String code) throws UserException {
		userService.createEmailVerificationCode(email, code);
	}

	@Override
	public String verifyEmailByCode(String code) throws UserException {
		final String email = userService.getEmailByVerificationCode(code);
		if (email == null)
			return null;

		User u = loadUser(email);
		if (u == null) {
			// TODO: Log an internal error. This should never happen.
			throw new NoSuchUserException("Failed to find a user with the given email: " + email);
		}

		userService.emailVerified(u.id);
		userService.deleteEmailVerificationCode(code);

		return email;
	}
}
