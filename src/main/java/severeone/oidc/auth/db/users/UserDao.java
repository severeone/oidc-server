package severeone.oidc.auth.db.users;

import severeone.oidc.auth.core.User;

import org.jdbi.v3.sqlobject.SingleValue;
import org.jdbi.v3.sqlobject.config.RegisterConstructorMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;

import java.sql.Timestamp;
import java.util.List;

public interface UserDao {
	@SqlUpdate("INSERT INTO users(type, email, password, first_name, last_name, created, verified) " +
			"VALUES (?, ?, ?, ?, ?, ?, ?)")
	void createUser(int userType, String email, String password, String firstName, String lastName,
	                Timestamp createdAt, boolean emailVerified);

	@SqlQuery("SELECT * FROM users WHERE email = ?")
	@RegisterConstructorMapper(User.class)
	@SingleValue
	User getUserByEmail(String email);

	@SqlQuery("SELECT * FROM users WHERE id = ?")
	@RegisterConstructorMapper(User.class)
	@SingleValue
	User getUserById(int id);

	@SqlUpdate("UPDATE users SET email = :email, first_name = :fn, last_name = :ln WHERE id = :id")
	void updateUserInfo(@Bind("id") int id, @Bind("email") String email, @Bind("fn") String firstName,
	                    @Bind("ln") String lastName);

	@SqlUpdate("UPDATE users SET password = :password WHERE id = :id")
	void setPassword(@Bind("id") int id, @Bind("password") String password);

	@SqlUpdate("UPDATE users SET verified = TRUE WHERE id = ?")
	void setEmailVerified(int id);

	@SqlUpdate("UPDATE users SET type = :type WHERE id = :id")
	void updateUserType(@Bind("id") int id, @Bind("type") int userType);

	@SqlUpdate("DELETE FROM users WHERE id = ?")
	void deleteUser(int id);

	@SqlUpdate("DELETE FROM auth_sessions WHERE user_id = ?")
	void deleteUserAuthSessions(int id);

	@SqlUpdate("DELETE FROM tokens WHERE user_id = ?")
	void deleteUserTokens(int id);

	@SqlQuery("SELECT type FROM user_account_types")
	List<Integer> getUserTypes();

	@SqlQuery("SELECT description FROM user_account_types WHERE type = ?")
	@SingleValue
	String getUserType(int type);

	@SqlUpdate("INSERT INTO email_verification_codes(email, code) VALUES (?, ?)")
	void createEmailVerificationCode(String email, String code);

	@SqlQuery("SELECT email FROM email_verification_codes WHERE code = ?")
	@SingleValue
	String getEmailByVerificationCode(String code);

	@SqlUpdate("DELETE FROM email_verification_codes WHERE code = ?")
	void deleteEmailVerificationCode(String code);
}
