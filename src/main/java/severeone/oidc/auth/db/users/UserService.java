package severeone.oidc.auth.db.users;

import severeone.oidc.auth.core.User;
import severeone.oidc.auth.core.UserType;

// UserService is a backend service for creating and managing users of the platform.
public interface UserService {
	// createUser creates a new user of a given type with the given name and email address.
	// createUser is idempotent - Repeated calls with the same email address will not
	// create new users. They will return null if a user with the given email exists.
	// Throws an exception (NoSuchUserTypeException) if no such user type exists.
	// Throws an exception (IncompleteUserException) if an email and/or password are not specified.
	User createUser(UserType userType, String email, String password, String firstName, String lastName)
			throws UserException;

	// getUserByEmail should return the user with the given email address.
	// Returns null if this user does not exist.
	User getUserByEmail(String email) throws UserException;

	// getUserById should return the user with the given id.
	// Returns null if this user does not exist.
	User getUserById(int id) throws UserException;

	// updateUserInfo changes the given user's email, first and last names.
	// Throws an exception (NoSuchUserException) if no user exists with that id.
	// Throws an exception (DuplicateUserException) if a user with a specified email already exists.
	// Throws an exception (IncompleteUserException) if an email is not specified.
	void updateUserInfo(int id, String email, String firstName, String lastName) throws UserException;

	// setPassword changes the password for a given user.
	// Throws an exception (NoSuchUserException) if no user exists with that id.
	// Throws an exception (IncompleteUserException) if a password is not specified.
	void setPassword(int id, String password) throws UserException;

	// setEmailVerified marks an email for the given user as verified.
	// Throws an exception (NoSuchUserException) if no user exists with that id.
	void emailVerified(int id) throws UserException;

	// updateUserType changes the type of the given user.
	// Throws an exception (NoSuchUserException) if no user exists with that id.
	// Throws an exception (NoSuchUserTypeException) if no such user type exists.
	void updateUserType(int id, UserType userType) throws UserException;

	// deleteUser removes a user with the specified id from the db.
	// Throws an exception (NoSuchUserException) if no user exists with that id.
	void deleteUser(int id) throws UserException;

	// getUserType should return the description of the given user type.
	// Returns null if this user type does not exist.
	String getUserType(UserType userType) throws UserException;

	// createEmailVerificationCode creates a verification record with email and code.
    void createEmailVerificationCode(String email, String code) throws UserException;

    // getEmailByVerificationCode should return the email associated with the given verification code.
	// Returns null if no such code registered.
	String getEmailByVerificationCode(String code) throws UserException;

	// deleteEmailVerificationCode removes a record with the specified verification code from the db.
	// Throws an exception (NoSuchEmailVerificationCodeException) if no record exists with that code.
	void deleteEmailVerificationCode(String code) throws UserException;
}
