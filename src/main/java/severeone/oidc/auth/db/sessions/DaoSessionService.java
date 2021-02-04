package severeone.oidc.auth.db.sessions;

import severeone.oidc.auth.db.users.NoSuchUserException;
import severeone.oidc.auth.db.users.NoSuchUserTypeException;
import severeone.oidc.auth.db.users.UserException;
import severeone.oidc.auth.db.users.UserService;

import severeone.oidc.auth.core.*;
import org.apache.commons.lang3.exception.ExceptionUtils;

import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.core.JdbiException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.MalformedURLException;
import java.net.URL;
import java.sql.Timestamp;
import java.util.List;

public class DaoSessionService implements SessionService {

	private static final Logger LOGGER = LoggerFactory.getLogger(DaoSessionService.class);
	private final SessionDao sessionDao;
	private UserService userService;

	public DaoSessionService(Jdbi jdbi, UserService userService) {
		this.sessionDao = jdbi.onDemand(SessionDao.class);
		this.userService = userService;
	}

	@Override
	public Session createSession(String authorizationCode, String clientId, int userId, URL redirectUri,
                                 String nonce, Timestamp validTill) throws SessionException, UserException {
		try {
			// Check if a session with a specified code exists.
			// It's a unique field so we return an existing session unchanged.
			Session s = getSession(authorizationCode);
			if (s != null)
				return s;

			// Check if a user with the specified ID exists
			if (userService.getUserById(userId) == null) {
				throw new NoSuchUserException(String.valueOf(userId));
			}

			// Check if a client with the specified ID exists
			Client client = getClient(clientId);
			if (client == null) {
				throw new NoSuchClientException(clientId);
			}

			// Check if required fields (code and uri) are specified.
			if (authorizationCode.isEmpty())
				throw new IncompleteSessionException("Authorization Code");
			if (redirectUri == null)
				throw new IncompleteSessionException("redirect URI");

			if (!client.containsRedirectUri(redirectUri))
				throw new InvalidRedirectUriException(clientId + " " + redirectUri.toString());

			// Create a record for a new session in auth_sessions table.
			try {
				sessionDao.createSession(authorizationCode, clientId, userId, validTill, redirectUri.toString(), nonce);
			} catch (JdbiException e) {
				throw new SessionException(String.format("Failed to create a new session record in auth_sessions table: %s.",
						ExceptionUtils.getMessage(e)));
			}

			// Extract a newly created session from the DB.
			s = getSession(authorizationCode);
			if (s == null) {
				throw new SessionException(String.format("Failed to extract a newly created session with code %s.",
						authorizationCode));
			}
			return s;
		} catch (Exception ex) {
			LOGGER.error(ex.getMessage());
			throw ex;
		}
	}

	@Override
	public Session getSession(String authorizationCode) throws SessionException {
		Session s;
		try {
			s = sessionDao.getSession(authorizationCode);
		} catch (JdbiException e) {
			String msg = String.format("Failed to get a session by code %s: %s.",
					authorizationCode, ExceptionUtils.getMessage(e));
			LOGGER.error(msg);
			throw new SessionException(msg);
		}
		return s;
	}

	@Override
	public void deleteSession(String authorizationCode) throws SessionException {
		try {
			// Check if a session with the specified code exists.
			Session s = getSession(authorizationCode);
			if (s == null)
				throw new NoSuchSessionException(authorizationCode);

			try {
				sessionDao.deleteSession(authorizationCode);
			} catch (JdbiException e) {
				throw new SessionException(String.format("Failed to delete a session with code %s: %s.",
						authorizationCode, ExceptionUtils.getMessage(e)));
			}
		} catch (Exception ex) {
			LOGGER.error(ex.getMessage());
			throw ex;
		}
	}

	@Override
	public Client getClient(String id) throws SessionException {
		try {
			// Extract client from clients table.
			Client c;
			try {
				c = sessionDao.getClient(id);
			} catch (JdbiException e) {
				throw new SessionException(String.format("Failed to get a client by id %s: %s.", id, e.getMessage()));
			}

			// Extract client's redirect URIs from client_redirect_uris table.
			List<String> redirectUris;
			try {
				redirectUris = sessionDao.getRedirectUris(id);
			} catch (JdbiException e) {
				throw new SessionException(String.format("Failed to get client's redirect URIs id %s: %s.", id, e.getMessage()));
			}

			// Add extracted URIs to a client
			try {
				for (String uri: redirectUris)
					c.addRedirectUris(new URL(uri));
			} catch (MalformedURLException e) {
				throw new SessionException(String.format("Failed to add malformed URL to a client %s: %s.", id, e.getMessage()));
			}

			return c;
		} catch (Exception ex) {
			LOGGER.error(ex.getMessage());
			throw ex;
		}
	}

	@Override
	public TokensLifeTime getTokensLifeTime(UserType userType, String clientId) throws SessionException, UserException {
		try {
			// Check if the given user type exists.
			if (userService.getUserType(userType) == null)
				throw new NoSuchUserTypeException(userType.toString());

			// Check if the given client id exists.
			if (getClient(clientId) == null)
				throw new NoSuchClientException(clientId);

			TokensLifeTime tlt;
			try {
				tlt = sessionDao.getTokensLifeTime(userType.ordinal(), clientId);
			} catch (JdbiException e) {
				throw new SessionException(String.format(
						"Failed to get tokens life time for user type %d and client id %s: %s.",
						userType.ordinal(), clientId, e.getMessage()));
			}
			return tlt;
		} catch (Exception ex) {
			LOGGER.error(ex.getMessage());
			throw ex;
		}
	}

	@Override
	public AccessData createTokensRecord(String refreshToken, String encryptedAccessToken, String clientId, int userId)
			throws SessionException {
		try {
			// Check if a tokens record with a specified refresh token exists.
			AccessData ad = getTokensRecord(refreshToken);
			if (ad != null)
				throw new DuplicateTokenException("refresh token", refreshToken);

			// Check if a tokens record with a specified access token hash exists.
			ad = getTokensRecordByEncryptedAccessToken(encryptedAccessToken);
			if (ad != null)
				throw new DuplicateTokenException("encrypted access token", encryptedAccessToken);

			// Check if a client with the specified ID exists
			Client client = getClient(clientId);
			if (client == null) {
				throw new NoSuchClientException(clientId);
			}

			// Check if required fields (tokens) are specified.
			if (refreshToken.isEmpty())
				throw new IncompleteTokensRecordException("refresh token");
			if (encryptedAccessToken.isEmpty())
				throw new IncompleteTokensRecordException("encrypted access token");

			// Create a new tokens record in tokens table.
			try {
				sessionDao.createTokensRecord(refreshToken, encryptedAccessToken, clientId, userId);
			} catch (JdbiException e) {
				throw new SessionException(String.format("Failed to create a new tokens record in tokens table: %s.",
						ExceptionUtils.getMessage(e)));
			}

			// Extract a newly created user from the DB.
			ad = getTokensRecord(refreshToken);
			if (ad == null) {
				throw new SessionException(String.format("Failed to extract a newly created tokens record with a refresh token %s.",
						refreshToken));
			}
			return ad;
		} catch (Exception ex) {
			LOGGER.error(ex.getMessage());
			throw ex;
		}
	}

	@Override
	public AccessData getTokensRecord(String refreshToken) throws SessionException {
		AccessData ad;
		try {
			ad = sessionDao.getTokensRecordByRefreshToken(refreshToken);
		} catch (JdbiException e) {
			String msg = String.format("Failed to get a tokens record by a refresh token %s: %s.",
					refreshToken, ExceptionUtils.getMessage(e));
			LOGGER.error(msg);
			throw new SessionException(msg);
		}
		return ad;
	}

	private AccessData getTokensRecordByEncryptedAccessToken(String encryptedAccessToken) throws SessionException {
		AccessData ad;
		try {
			ad = sessionDao.getTokensRecordByEncryptedAccessToken(encryptedAccessToken);
		} catch (JdbiException e) {
			String msg = String.format("Failed to get a tokens record by an access token hash %s: %s.",
					encryptedAccessToken, ExceptionUtils.getMessage(e));
			LOGGER.error(msg);
			throw new SessionException(msg);
		}
		return ad;
	}

	@Override
	public void deleteTokensRecord(String encryptedAccessToken) throws SessionException {
		try {
			// Check if a tokens record with the specified encrypted access token exists.
			AccessData ad = getTokensRecordByEncryptedAccessToken(encryptedAccessToken);
			if (ad == null)
				throw new NoSuchTokenException(encryptedAccessToken);

			try {
				sessionDao.deleteTokensRecord(encryptedAccessToken);
			} catch (JdbiException e) {
				throw new SessionException(String.format("Failed to delete a tokens record with an encrypted access token %s: %s.",
						encryptedAccessToken, ExceptionUtils.getMessage(e)));
			}
		} catch (Exception ex) {
			LOGGER.error(ex.getMessage());
			throw ex;
		}
	}
}
