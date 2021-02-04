package severeone.oidc.auth.db.users;

import severeone.oidc.auth.core.User;
import severeone.oidc.auth.core.UserType;

import severeone.oidc.auth.util.Utilities;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.core.JdbiException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Timestamp;
import java.util.List;

public class DaoUserService implements UserService {

	private static final Logger LOGGER = LoggerFactory.getLogger(DaoUserService.class);
	private final UserDao userDao;

	public DaoUserService(Jdbi jdbi) {
		this.userDao = jdbi.onDemand(UserDao.class);
	}

	@Override
	public User createUser(UserType userType, String email, String password, String firstName, String lastName)
			throws UserException {
		try {
			// Extract a list of user account types from the DB
			List<Integer> userTypes = null;
			try {
				userTypes = userDao.getUserTypes();
			} catch (JdbiException e) {
				throw new UserException(String.format("Failed to get user account types from DB: %s.",
						ExceptionUtils.getMessage(e)));
			}

			// Check if the specified user type exists
			if (!userTypes.contains(userType.ordinal())) {
				throw new NoSuchUserTypeException(String.valueOf(userType));
			}

			// Check if required fields (email and password) are specified.
			if (email.isEmpty())
				throw new IncompleteUserException("email");
			if (password.isEmpty())
				throw new IncompleteUserException("password");

			// Check if a user with a specified email exists.
			// It's a unique field so we return null.
			User u = getUserByEmail(email);
			if (u != null)
				return null;

			// Create a record for a new user in users table.
			try {
				userDao.createUser(userType.ordinal(), email, Utilities.hash(password), firstName, lastName,
						new Timestamp(System.currentTimeMillis()), false);
			} catch (JdbiException e) {
				throw new UserException(String.format("Failed to create a new user record in users table: %s.",
						ExceptionUtils.getMessage(e)));
			}

			// Extract a newly created user from the DB to get its id and password hash
			// and to check if it was correctly inserted.
			u = getUserByEmail(email);
			if (u == null) {
				throw new UserException(String.format("Failed to extract a newly created user with email %s.", email));
			}
			return u;
		} catch (Exception ex) {
			LOGGER.error(ex.getMessage());
			throw ex;
		}
	}

	@Override
	public User getUserByEmail(String email) throws UserException {
		User u;
		try {
			u = userDao.getUserByEmail(email);
		} catch (JdbiException e) {
			String msg = String.format("Failed to get a user by email %s: %s.",
					email, ExceptionUtils.getMessage(e));
			LOGGER.error(msg);
			throw new UserException(msg);
		}
		return u;
	}

	@Override
	public User getUserById(int id) throws UserException {
		User u;
		try {
			u = userDao.getUserById(id);
		} catch (JdbiException e) {
			String msg = String.format("Failed to get a user by id %d: %s.",
					id, ExceptionUtils.getMessage(e));
			LOGGER.error(msg);
			throw new UserException(msg);
		}
		return u;
	}

	@Override
	public void updateUserInfo(int id, String email, String firstName, String lastName) throws UserException {
		try {
			// Check if a user with the specified id exists.
			User u = getUserById(id);
			if (u == null)
				throw new NoSuchUserException(Integer.toString(id));

			// Check if a required field (email) is specified.
			if (email == null || email.isEmpty())
				throw new IncompleteUserException("email");

			// Check if a user with a specified email exists.
			// We cannot allow two users with the same email to exist.
			User other = getUserByEmail(email);
			if (other != null && u.id != other.id)
				throw new DuplicateUserException(String.format(" id %d and id %d, email %s", id, u.id, email));

			try {
				userDao.updateUserInfo(id, email, firstName, lastName);
			} catch (JdbiException e) {
				throw new UserException(String.format("Failed to update a user with id %d: %s.",
						id, ExceptionUtils.getMessage(e)));
			}
		} catch (Exception ex) {
			LOGGER.error(ex.getMessage());
			throw ex;
		}
	}

	@Override
	public void setPassword(int id, String password) throws UserException {
		try {
			// Check if a user with the specified id exists.
			User u = getUserById(id);
			if (u == null)
				throw new NoSuchUserException(Integer.toString(id));

			// Check if a required field (password) is specified.
			if (password == null || password.isEmpty())
				throw new IncompleteUserException("password");

			try {
				userDao.setPassword(id, Utilities.hash(password));
			} catch (JdbiException e) {
				throw new UserException(String.format("Failed to set a new password for a user with id %d: %s.",
						id, ExceptionUtils.getMessage(e)));
			}
		} catch (Exception ex) {
			LOGGER.error(ex.getMessage());
			throw ex;
		}
	}

	@Override
	public void emailVerified(int id) throws UserException {
		try {
			// Check if a user with the specified id exists.
			User u = getUserById(id);
			if (u == null)
				throw new NoSuchUserException(Integer.toString(id));

			try {
				userDao.setEmailVerified(id);
			} catch (JdbiException e) {
				throw new UserException(String.format("Failed to set an email verification flag for a user with id %d: %s.",
						id, ExceptionUtils.getMessage(e)));
			}
		} catch (Exception ex) {
			LOGGER.error(ex.getMessage());
			throw ex;
		}
	}

	@Override
	public void updateUserType(int id, UserType userType) throws UserException {
		try {
			// Extract a list of user account types from the DB
			List<Integer> userTypes;
			try {
				userTypes = userDao.getUserTypes();
			} catch (JdbiException e) {
				throw new UserException(String.format("Failed to get user account types from DB: %s.",
						ExceptionUtils.getMessage(e)));
			}

			// Check if the specified user type exists
			if (!userTypes.contains(userType.ordinal()))
				throw new NoSuchUserTypeException(String.valueOf(userType));

			// Check if a user with the specified id exists.
			User u = getUserById(id);
			if (u == null)
				throw new NoSuchUserException(Integer.toString(id));

			try {
				userDao.updateUserType(id, userType.ordinal());
			} catch (JdbiException e) {
				throw new UserException(String.format("Failed to set a new user type for a user with id %d: %s.",
						id, ExceptionUtils.getMessage(e)));
			}
		} catch (Exception ex) {
			LOGGER.error(ex.getMessage());
			throw ex;
		}
	}

	@Override
	public void deleteUser(int id) throws UserException {
		try {
			// Check if a user with the specified id exists.
			User u = getUserById(id);
			if (u == null)
				throw new NoSuchUserException(Integer.toString(id));

			try {
				userDao.deleteUserAuthSessions(id);
				userDao.deleteUserTokens(id);
				userDao.deleteUser(id);
			} catch (JdbiException e) {
				throw new UserException(String.format("Failed to delete a user with id %d: %s.",
						id, ExceptionUtils.getMessage(e)));
			}
		} catch (Exception ex) {
			LOGGER.error(ex.getMessage());
			throw ex;
		}
	}

	@Override
	public String getUserType(UserType userType) throws UserException {
		String description;
		try {
			description = userDao.getUserType(userType.ordinal());
		} catch (JdbiException e) {
			String msg = String.format("Failed to get a user type from DB: %s.",
					ExceptionUtils.getMessage(e));
			LOGGER.error(msg);
			throw new UserException(msg);
		}
		return description;
	}

	@Override
	public void createEmailVerificationCode(String email, String code) throws UserException {
		try {
			userDao.createEmailVerificationCode(email, code);
		} catch (JdbiException e) {
			throw new UserException(String.format("Failed to create a new verification code record (%s, %s): %s",
					email, code, ExceptionUtils.getMessage(e)));
		}
	}

	@Override
	public String getEmailByVerificationCode(String code) throws UserException {
		String email;
		try {
			email = userDao.getEmailByVerificationCode(code);
		} catch (JdbiException e) {
			throw new UserException(String.format("Failed to get an email by code %s: %s.",
					code, ExceptionUtils.getMessage(e)));
		}
		return email;
	}

	@Override
	public void deleteEmailVerificationCode(String code) throws UserException {
		if (getEmailByVerificationCode(code) == null)
			throw new NoSuchEmailVerificationCodeException(code);

		try {
			userDao.deleteEmailVerificationCode(code);
		} catch (JdbiException e) {
			throw new UserException(String.format("Failed to delete a verification code %s: %s.",
					code, ExceptionUtils.getMessage(e)));
		}
	}
}
