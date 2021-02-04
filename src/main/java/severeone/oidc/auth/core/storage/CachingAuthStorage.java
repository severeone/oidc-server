package severeone.oidc.auth.core.storage;

import severeone.oidc.auth.core.*;
import severeone.oidc.auth.db.sessions.SessionException;
import severeone.oidc.auth.db.users.UserException;

import java.net.URL;
import java.sql.Timestamp;

public class CachingAuthStorage implements AuthStorage {

    final private String AUTH_KEY_PREFIX = "auth";
    final private String ACCESS_KEY_PREFIX = "access";
    final private String REFRESH_KEY_PREFIX = "refresh";

    private AuthStorage storage;
    private StorageCache cache;

    public CachingAuthStorage(AuthStorage storage, StorageCache cache) {
        this.storage = storage;
        this.cache = cache;
    }

    private String makeKey(String keyPrefix, String key) {
        return keyPrefix + "/" + key;
    }

    @Override
    public Session saveAuthorizationData(String authorizationCode, String clientId, int userId,
                                         URL redirectUri, String nonce, Timestamp validTill)
            throws UserException, SessionException {
        Session s = storage.saveAuthorizationData(authorizationCode, clientId, userId, redirectUri, nonce, validTill);
        if (s != null)
            cache.set(makeKey(AUTH_KEY_PREFIX, authorizationCode), new Session(s));
        return s;
    }

    @Override
    public Session loadAuthorizationData(String authorizationCode) throws SessionException {
        String key = makeKey(AUTH_KEY_PREFIX, authorizationCode);
        Session res = null;

        // Try to find the key in cache
        Object cached = cache.get(key);
        if (cached != null) {
            if (cached instanceof Session) {
                res = (Session) cached;
            } else {
                // TODO: Log this error
                cache.remove(key);
            }
        }
        if (res != null) {
            return res;
        }

        // Cache lookup failed; search for the key in storage.
        return storage.loadAuthorizationData(authorizationCode);
    }

    @Override
    public boolean removeAuthorizationData(String authorizationCode) throws SessionException {
        cache.remove(makeKey(AUTH_KEY_PREFIX, authorizationCode));
        return storage.removeAuthorizationData(authorizationCode);
    }

    @Override
    public AccessData saveAccessData(String refreshToken, String encryptedAccessToken, String clientId, int userId)
            throws SessionException {
        AccessData ad = storage.saveAccessData(refreshToken, encryptedAccessToken, clientId, userId);
        if (ad != null) {
            cache.set(makeKey(ACCESS_KEY_PREFIX, encryptedAccessToken), ad);
            cache.set(makeKey(REFRESH_KEY_PREFIX, refreshToken), ad);
        }
        return ad;
    }

    @Override
    public AccessData loadAccessData(String refreshToken) throws SessionException {
        String key = makeKey(REFRESH_KEY_PREFIX, refreshToken);
        AccessData res = null;

        // Try to find the key in cache
        Object cached = cache.get(key);
        if (cached != null) {
            if (cached instanceof AccessData) {
                res = (AccessData) cached;
            } else {
                // TODO: Log this error
                cache.remove(key);
            }
        }
        if (res != null) {
            return res;
        }

        // Cache lookup failed; search for the key in storage.
        return storage.loadAccessData(refreshToken);
    }

    @Override
    public boolean removeAccessData(String encryptedAccessToken) throws SessionException {
        String key = makeKey(ACCESS_KEY_PREFIX, encryptedAccessToken);

        Object cached = cache.get(key);
        if (cached != null) {
            if (cached instanceof AccessData) {
                cache.remove(key);
                cache.remove(makeKey(REFRESH_KEY_PREFIX, ((AccessData)cached).refreshToken));
            } else {
                // TODO: Log this error
            }
        }

        return storage.removeAccessData(encryptedAccessToken);
    }

    @Override
    public TokensLifeTime loadTokensLifeTime(UserType userType, String clientId)
            throws SessionException, UserException {
        return storage.loadTokensLifeTime(userType, clientId);
    }

    @Override
    public Client loadClient(String clientId) throws SessionException {
        return storage.loadClient(clientId);
    }

    @Override
    public User loadUser(String email) throws UserException {
        return storage.loadUser(email);
    }

    @Override
    public User loadUser(int id) throws UserException {
        return storage.loadUser(id);
    }

    @Override
    public User saveUser(UserType userType, String email, String password, String firstName, String lastName)
            throws UserException {
        return storage.saveUser(userType, email, password, firstName, lastName);
    }

    @Override
    public void updateUser(int id, String email, String firstName, String lastName, String password, UserType userType)
            throws UserException {
        storage.updateUser(id, email, firstName, lastName, password, userType);
    }

    @Override
    public boolean deleteUser(int id) throws UserException {
        return storage.deleteUser(id);
    }

    @Override
    public void saveEmailVerificationCode(String email, String code) throws UserException {
        storage.saveEmailVerificationCode(email, code);
    }

    @Override
    public String verifyEmailByCode(String code) throws UserException {
        return storage.verifyEmailByCode(code);
    }
}
