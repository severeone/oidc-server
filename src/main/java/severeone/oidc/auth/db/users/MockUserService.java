package severeone.oidc.auth.db.users;

import severeone.oidc.auth.core.User;
import severeone.oidc.auth.core.UserType;
import severeone.oidc.auth.util.Utilities;

import java.sql.Timestamp;
import java.util.*;

public class MockUserService implements UserService {

	private static Set<Integer> USER_TYPES = new HashSet<>();

	private List<User> usersById = new ArrayList<>();
	private Map<String, User> usersByEmail = new HashMap<>();
	private Map<String, String> emailsByVerificationCode = new HashMap<>();

	public MockUserService(int userTypesCount) {
		for (int i = 0; i <= userTypesCount; ++i)
			USER_TYPES.add(i);
	}

	@Override
	public User createUser(UserType userType, String email, String password, String firstName, String lastName)
			throws UserException {
		if (usersByEmail.containsKey(email))
			return null;
		if (!USER_TYPES.contains(userType.ordinal()) || userType == UserType.INVALID)
			throw new NoSuchUserTypeException(String.valueOf(userType));
		if (email.isEmpty())
			throw new IncompleteUserException("email");
		if (password.isEmpty())
			throw new IncompleteUserException("password");
		User u = new User(usersById.size(), userType, email, firstName, lastName, Utilities.hash(password),
				new Timestamp(System.currentTimeMillis()));
		usersById.add(new User(u));
		usersByEmail.put(email, new User(u));
		return u;
	}

	@Override
	public User getUserByEmail(String email) throws UserException {
		if (!usersByEmail.containsKey(email))
			return null;
		return new User(usersByEmail.get(email));
	}

	@Override
	public User getUserById(int id) throws UserException {
		if (id >= usersById.size() || usersById.get(id) == null)
			return null;
		return new User(usersById.get(id));
	}

	@Override
	public void updateUserInfo(int id, String email, String firstName, String lastName) throws UserException {
		User u = getUserById(id);
		if (u == null)
			throw new NoSuchUserException(String.valueOf(id));
		if (!u.email.equals(email) && usersByEmail.containsKey(email))
			throw new DuplicateUserException("id " + usersByEmail.get(email).id);
		if (email == null || email.isEmpty())
			throw new IncompleteUserException("email");
		usersByEmail.remove(u.email);
		u.email = email;
		u.firstName = firstName;
		u.lastName = lastName;
		usersById.set(id, u);
		usersByEmail.put(email, new User(u));
	}

	@Override
	public void setPassword(int id, String password) throws UserException {
		User u = getUserById(id);
		if (u == null)
			throw new NoSuchUserException(String.valueOf(id));
		if (password == null || password.isEmpty())
			throw new IncompleteUserException("password");
		u.passwordHash = Utilities.hash(password);
		usersById.set(id, u);
		usersByEmail.replace(u.email, new User(u));
	}

	@Override
	public void emailVerified(int id) throws UserException {
		User u = getUserById(id);
		if (u == null)
			throw new NoSuchUserException(String.valueOf(id));
		u.emailVerified = true;
		usersById.set(id, u);
		usersByEmail.replace(u.email, new User(u));
	}

	@Override
	public void updateUserType(int id, UserType userType) throws UserException {
		if (!USER_TYPES.contains(userType.ordinal()))
			throw new NoSuchUserTypeException(String.valueOf(userType));
		User u = getUserById(id);
		if (u == null)
			throw new NoSuchUserException(String.valueOf(id));
		u.type = userType;
		usersById.set(id, u);
		usersByEmail.replace(u.email, new User(u));
	}

	@Override
	public void deleteUser(int id) throws UserException {
		User u = getUserById(id);
		if (u == null)
			throw new NoSuchUserException(String.valueOf(id));
		usersByEmail.remove(u.email);
		usersById.set(id, null);
	}

	@Override
	public String getUserType(UserType userType) throws UserException {
		if (!USER_TYPES.contains(userType.ordinal()) || userType == UserType.INVALID)
			return null;
		return userType.name();
	}

	@Override
	public void createEmailVerificationCode(String email, String code) throws UserException {
		emailsByVerificationCode.put(code, email);
	}

	@Override
	public String getEmailByVerificationCode(String code) throws UserException {
		if (emailsByVerificationCode.containsKey(code))
			return emailsByVerificationCode.get(code);
		return null;
	}

	@Override
	public void deleteEmailVerificationCode(String code) throws UserException {
		if (getEmailByVerificationCode(code) == null)
			throw new NoSuchEmailVerificationCodeException(code);
		emailsByVerificationCode.remove(code);
	}
}
