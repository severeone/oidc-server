package severeone.oidc.auth.core;

import java.beans.ConstructorProperties;
import java.sql.Timestamp;

public class User {

	public int id;
	public UserType type;
	public String email;
	public String firstName;
	public String lastName;
	public Timestamp createdAt;
	public String passwordHash;
	public boolean emailVerified;

	public User(int id, UserType type, String email, String firstName, String lastName, String passwordHash,
	            Timestamp createdAt) {
		this.id = id;
		this.type = type;
		this.email = email;
		this.firstName = firstName;
		this.lastName = lastName;
		this.passwordHash = passwordHash;
		this.createdAt = createdAt;
		this.emailVerified = false;
	}

	@ConstructorProperties({"id", "type", "email", "first_name", "last_name", "password", "created", "verified"})
	public User(int id, int type, String email, String firstName, String lastName, String passwordHash,
	            Timestamp createdAt, boolean emailVerified) {
		this.id = id;
		this.type = UserType.values()[type];
		this.email = email;
		this.firstName = firstName;
		this.lastName = lastName;
		this.createdAt = createdAt;
		this.passwordHash = passwordHash;
		this.emailVerified = emailVerified;
	}

	public User(User other) {
		this.id = other.id;
		this.type = other.type;
		this.email = other.email;
		this.firstName = other.firstName;
		this.lastName = other.lastName;
		this.createdAt = new Timestamp(other.createdAt.getTime());
		this.passwordHash = other.passwordHash;
		this.emailVerified = other.emailVerified;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		User other = (User) o;
		return id == other.id &&
				type == other.type &&
				email.equals(other.email) &&
				firstName.equals(other.firstName) &&
				lastName.equals(other.lastName) &&
				passwordHash.equals(other.passwordHash) &&
				createdAt.equals(other.createdAt) &&
				emailVerified == other.emailVerified;
	}
}
