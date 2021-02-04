package severeone.oidc.auth.db.sessions;

import severeone.oidc.auth.core.AccessData;
import severeone.oidc.auth.core.Session;
import severeone.oidc.auth.core.Client;

import severeone.oidc.auth.core.TokensLifeTime;
import org.jdbi.v3.sqlobject.SingleValue;
import org.jdbi.v3.sqlobject.config.RegisterConstructorMapper;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;

import java.sql.Timestamp;
import java.util.List;

public interface SessionDao {
	@SqlUpdate("INSERT INTO auth_sessions(code, client_id, user_id, valid_till, redirect_uri, nonce) " +
			"VALUES (?, ?, ?, ?, ?, ?)")
	void createSession(String authorizationCode, String clientId, int userId, Timestamp validTill, String redirectUri,
	                   String nonce);

	@SqlQuery("SELECT * FROM auth_sessions WHERE code = ?")
	@RegisterConstructorMapper(Session.class)
	@SingleValue
	Session getSession(String authorizationCode);

	@SqlUpdate("DELETE FROM auth_sessions WHERE code = ?")
	void deleteSession(String authorizationCode);

	@SqlQuery("SELECT * FROM clients WHERE id = ?")
	@RegisterConstructorMapper(Client.class)
	@SingleValue
	Client getClient(String id);

	@SqlQuery("SELECT * FROM tokens_life_time WHERE user_type = ? AND client_id = ?")
	@RegisterConstructorMapper(TokensLifeTime.class)
	@SingleValue
	TokensLifeTime getTokensLifeTime(int userType, String clientId);

	@SqlQuery("SELECT redirect_uri FROM client_redirect_uris WHERE id = ?")
	List<String> getRedirectUris(String id);

	@SqlUpdate("INSERT INTO tokens(refresh_token, encrypted_access_token, client_id, user_id) VALUES (?, ?, ?, ?)")
	void createTokensRecord(String refreshToken, String encryptedAccessToken, String clientId, int userId);

	@SqlQuery("SELECT * FROM tokens WHERE refresh_token = ?")
	@RegisterConstructorMapper(AccessData.class)
	@SingleValue
	AccessData getTokensRecordByRefreshToken(String refreshToken);

	@SqlQuery("SELECT * FROM tokens WHERE encrypted_access_token = ?")
	@RegisterConstructorMapper(AccessData.class)
	@SingleValue
	AccessData getTokensRecordByEncryptedAccessToken(String encryptedAccessToken);

	@SqlUpdate("DELETE FROM tokens WHERE encrypted_access_token = ?")
	void deleteTokensRecord(String encryptedAccessToken);
}
