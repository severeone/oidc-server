package severeone.oidc.auth.core.storage;

import severeone.oidc.auth.core.*;
import severeone.oidc.auth.db.sessions.SessionException;
import severeone.oidc.auth.db.users.UserException;

import java.net.URL;
import java.sql.Timestamp;

// AuthStorage manages OIDC auth data, clients and tokens life time.
public interface AuthStorage {

	// saveAuthorizationData saves authorization data. Returns successfully created authorization Session.
	Session saveAuthorizationData(String authorizationCode, String clientId, int userId, URL redirectUri,
                                  String nonce, Timestamp validTill) throws UserException, SessionException;

	// loadAuthorizationData looks up authorization data by a code.
	// Returns null if there's no such Authorization Code registered.
	Session loadAuthorizationData(String authorizationCode) throws SessionException;

	// removeAuthorizationData revokes and deletes the Authorization Code.
	// Returns false if there's no such code registered.
	boolean removeAuthorizationData(String authorizationCode) throws SessionException;

	// saveAccessData writes the encrypted Access Token, user ID and the Refresh Token for the specified client ID.
	AccessData saveAccessData(String refreshToken, String encryptedAccessToken, String clientId, int userId)
			throws SessionException;

	// loadAccessData retrieves access data by Refresh Token.
	// Returns null if there's no such Refresh Token registered.
	AccessData loadAccessData(String refreshToken) throws SessionException;

	// removeAccessData revokes and deletes the Access Token.
	boolean removeAccessData(String encryptedAccessToken) throws SessionException;

	// loadTokensLifeTime looks up tokens life time by a user type and a client ID.
	TokensLifeTime loadTokensLifeTime(UserType userType, String clientId) throws SessionException, UserException;

	// loadClient looks up client by a client ID.
	Client loadClient(String clientId) throws SessionException;

	// loadUser looks up a user by email.
	User loadUser(String email) throws UserException;

	// loadUser looks up a user by id.
	User loadUser(int id) throws UserException;

	// saveUser creates a new user. Returns successfully created User or null if user exists.
	User saveUser(UserType userType, String email, String password, String firstName, String lastName)
			throws UserException;

	// updateUser updates a user profile defined by id.
	void updateUser(int id, final String email, final String firstName, final String lastName, final String password,
	                UserType userType) throws UserException;

	// deleteUser deletes a user profile.
	// Returns null if there's no such user ID registered.
	boolean deleteUser(int id) throws UserException;

	// saveEmailVerificationCode saves an email verification code.
	void saveEmailVerificationCode(String email, String code) throws UserException;

	// verifyEmailByCode searches for the given code, set email verified flag for a associated user and
	// removes the code if found. Returns null, if there's not such code registered,
	// otherwise returns a corresponding email.
	String verifyEmailByCode(String code) throws UserException;
}
