package severeone.oidc.auth.core.storage;

import severeone.oidc.auth.core.*;
import severeone.oidc.auth.db.sessions.MockSessionService;
import severeone.oidc.auth.db.sessions.SessionException;
import severeone.oidc.auth.db.sessions.SessionService;
import severeone.oidc.auth.db.users.*;
import severeone.oidc.auth.util.Utilities;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.Random;
import java.util.UUID;
import java.util.function.BiConsumer;
import java.util.function.Function;
import java.util.function.Supplier;

import static com.shazam.shazamcrest.matcher.Matchers.sameBeanAs;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.Assert.*;

@RunWith(Parameterized.class)
public class AuthStorageTest {

	private static MockUserService userService = new MockUserService(1);
	private static Client testClient = Utilities.createTestClient();
	private static TokensLifeTime testTokensLifeTime = Utilities.createTestTokensLifeTime();
	private static User testUser;
	private static Session session1, session2;
	private static AccessData accessData1, accessData2;

	static {
		try {
			testUser = userService.createUser(UserType.REGULAR, "rmarsh@me.com", "lorde", "Randy", "Marsh");
		} catch (UserException e) {
			fail("Failed to create a test user: " + e.getMessage());
		}
		session1 = new Session(
				"auth-code1",
				testClient.id,
				testUser.id,
				new Timestamp(System.currentTimeMillis()),
				Utilities.REDIRECT_URI_0,
				"noncenonce"
		);
		session2 = new Session(
				"auth-code2",
				testClient.id,
				testUser.id,
				new Timestamp(System.currentTimeMillis()),
				Utilities.REDIRECT_URI_1,
				"noncenoncenonce"
		);
		accessData1 = new AccessData(
				"access-token-hash1",
				"refresh-token1",
				testClient.id,
				testUser.id
		);
		accessData2 = new AccessData(
				"access-token-hash2",
				"refresh-token2",
				testClient.id,
				testUser.id
		);
	}

	private AuthStorage authStorage;

	public AuthStorageTest(String authStorageName, AuthStorage authStorage) {
		this.authStorage = authStorage;
	}

	interface DataSaver<T> { T save(T data); }
	interface DataLoader<T, K> { T load(K key); }
	interface DataRemover<K> { boolean remove(K key); }

	@Test
	public void authorizationDataTest() {
		DataSaver<Session> saver = s -> {
			Session actual = null;
			try {
				actual = authStorage.saveAuthorizationData(s.authorizationCode, s.clientId, s.userId, s.redirectUri,
						s.nonce, s.validTill);
			} catch (SessionException|UserException e) {
				fail("Failed to save authorization data: " + e.getMessage());
			}
			return actual;
		};

		DataLoader<Session, String> loader = ac -> {
			Session s = null;
			try {
				s = authStorage.loadAuthorizationData(ac);
			} catch (SessionException e) {
				fail("Failed to load authorization data: " + e.getMessage());
			}
			return s;
		};

		DataRemover<String> remover = ac -> {
			boolean res = false;
			try {
				res = authStorage.removeAuthorizationData(ac);
			} catch (SessionException e) {
				fail("Failed to remove authorization data: " + e.getMessage());
			}
			return res;
		};

		// Load not registered authorization codes
		assertNull(loader.load(session1.authorizationCode));
		assertNull(loader.load(session2.authorizationCode));
		// Remove not registered authorization codes
		assertFalse(remover.remove(session1.authorizationCode));
		assertFalse(remover.remove(session2.authorizationCode));
		// Create valid sessions
		assertThat(saver.save(session1), sameBeanAs(session1));
		assertThat(saver.save(session2), sameBeanAs(session2));
		// Load registered authorization codes
		assertThat(loader.load(session1.authorizationCode), sameBeanAs(session1));
		assertThat(loader.load(session2.authorizationCode), sameBeanAs(session2));
		// Remove registered authorization codes
		assertTrue(remover.remove(session1.authorizationCode));
		assertTrue(remover.remove(session2.authorizationCode));
		// Load removed authorization codes
		assertNull(loader.load(session1.authorizationCode));
		assertNull(loader.load(session2.authorizationCode));
	}

	@Test
	public void accessDataTest() {
		DataSaver<AccessData> saver = ad -> {
			AccessData actual = null;
			try {
				actual = authStorage.saveAccessData(ad.refreshToken, ad.encryptedAccessToken, ad.clientId, ad.userId);
			} catch (SessionException e) {
				fail("Failed to save access data: " + e.getMessage());
			}
			return actual;
		};

		DataLoader<AccessData, String> loader = rt -> {
			AccessData ad = null;
			try {
				ad = authStorage.loadAccessData(rt);
			} catch (SessionException e) {
				fail("Failed to load access data: " + e.getMessage());
			}
			return ad;
		};

		DataRemover<String> remover = ath -> {
			boolean res = false;
			try {
				res = authStorage.removeAccessData(ath);
			} catch (SessionException e) {
				fail("Failed to remove authorization data: " + e.getMessage());
			}
			return res;
		};

		// Load not registered access token hashes
		assertNull(loader.load(accessData1.refreshToken));
		assertNull(loader.load(accessData2.refreshToken));
		// Remove not registered refresh tokens
		assertFalse(remover.remove(accessData1.encryptedAccessToken));
		assertFalse(remover.remove(accessData2.encryptedAccessToken));
		// Create valid token records
		assertThat(saver.save(accessData1), sameBeanAs(accessData1));
		assertThat(saver.save(accessData2), sameBeanAs(accessData2));
		// Load registered refresh tokens
		assertThat(loader.load(accessData1.refreshToken), sameBeanAs(accessData1));
		assertThat(loader.load(accessData2.refreshToken), sameBeanAs(accessData2));
		// Remove registered access token hashes
		assertTrue(remover.remove(accessData1.encryptedAccessToken));
		assertTrue(remover.remove(accessData2.encryptedAccessToken));
		// Load removed refresh tokens
		assertNull(loader.load(accessData1.refreshToken));
		assertNull(loader.load(accessData2.refreshToken));
	}

	interface TokensLifeTimeLoader { TokensLifeTime load(UserType userType, String clientId); }

	@Test
	public void loadTokensLifeTime() {
		TokensLifeTimeLoader loader = (ut, ci) -> {
			TokensLifeTime tlt = null;
			try {
				tlt = authStorage.loadTokensLifeTime(ut, ci);
			} catch (SessionException|UserException e) {
				fail("Failed to load tokens life time: " + e.getMessage());
			}
			return tlt;
		};

		assertNull(loader.load(UserType.INVALID, testTokensLifeTime.clientId));
		assertNull(loader.load(testTokensLifeTime.userType, "mscrabtree"));
		assertThat(loader.load(testTokensLifeTime.userType, testTokensLifeTime.clientId), sameBeanAs(testTokensLifeTime));
	}

	@Test
	public void loadClient() {
		DataLoader<Client, String> loader = ci -> {
			Client c = null;
			try {
				c = authStorage.loadClient(ci);
			} catch (SessionException e) {
				fail("Failed to load client: " + e.getMessage());
			}
			return c;
		};

		assertNull(loader.load("mscrabtree"));
		assertThat(loader.load(testClient.id), sameBeanAs(testClient));
	}

	private DataLoader<User, String> userLoader = email -> {
		User u = null;
		try {
			u = authStorage.loadUser(email);
		} catch (UserException e) {
			fail("Failed to load user: " + e.getMessage());
		}
		return u;
	};

	private DataLoader<User, Integer> userLoaderById = email -> {
		User u = null;
		try {
			u = authStorage.loadUser(email);
		} catch (UserException e) {
			fail("Failed to load user: " + e.getMessage());
		}
		return u;
	};

	@Test
	public void loadUser() {
		assertNull(userLoader.load("mrhat@evil.com"));
		assertThat(userLoader.load(testUser.email), sameBeanAs(testUser).ignoring("passwordHash"));

		assertNull(userLoaderById.load(123));
		assertThat(userLoaderById.load(testUser.id), sameBeanAs(testUser).ignoring("passwordHash"));
	}

	private static int userCounter = 0;
	private static User additionalTestUser;

	@Test
	public void saveUser() {
		User expected = generateUser();

		Supplier<User> saver = () -> {
			User u = null;
			try {
				u = authStorage.saveUser(expected.type, expected.email, expected.passwordHash, expected.firstName,
						expected.lastName);
			} catch (UserException e) {
				fail("Failed to save a user");
			}
			return u;
		};

		User u = saver.get();
		assertNotNull(u);
		assertEquals(expected.email, u.email);
		assertTrue(Utilities.verifyHash(expected.passwordHash, u.passwordHash));
		assertEquals(expected.firstName, u.firstName);
		assertEquals(expected.lastName, u.lastName);

		assertNull(saver.get());

		assertThat(userLoader.load(u.email), sameBeanAs(u));

		additionalTestUser = u;
	}

	private User generateUser() {
		final UserType userType = UserType.REGULAR;
		final String email = String.format("mscrabtree%d@evil.com", ++userCounter);
		final String password = "manbearpig";
		final String firstName = "Miss";
		final String lastName = "Crabtree";

		return new User(0, userType, email, firstName, lastName, password, Timestamp.from(Instant.now()));
	}

	@Test
	public void updateUser() {
		final String email = "mrhat@fancypants.com";
		final String firstName = "Mister";
		final String lastName = "Hat";
		final String password = "chickenpox";
		UserType userType = UserType.INVALID;

		// Save additional user
		saveUser();

		assertThrows(NoSuchUserException.class, () -> authStorage.updateUser(1234135, email,
				firstName, lastName, password, userType));
		assertThrows(IncompleteUserException.class, () -> authStorage.updateUser(testUser.id, null,
				firstName, lastName, password, userType));
		assertThrows(DuplicateUserException.class, () -> authStorage.updateUser(testUser.id, additionalTestUser.email,
				firstName, lastName, password, userType));

		final User oldUser = testUser;
		try {
			authStorage.updateUser(testUser.id, email, firstName, lastName, password, userType);
		} catch (UserException e) {
			fail("Failed to update user");
		}

		User actualUser = userLoader.load(email);
		assertNotNull(actualUser);
		assertEquals(testUser.id, actualUser.id);
		assertEquals(email, actualUser.email);
		assertEquals(firstName, actualUser.firstName);
		assertEquals(lastName, actualUser.lastName);
		assertEquals(userType, actualUser.type);
		assertTrue(Utilities.verifyHash(password, actualUser.passwordHash));

		try {
			authStorage.updateUser(testUser.id, oldUser.email, oldUser.firstName, oldUser.lastName, "lorde", UserType.REGULAR);
		} catch (UserException e) {
			fail("Failed to update user");
		}
	}

	private DataRemover<Integer> userRemover = id -> {
		boolean res = false;
		try {
			res = authStorage.deleteUser(id);
		} catch (UserException e) {
			fail("Failed to delete user: " + e.getMessage());
		}
		return res;
	};

	@Test
	public void deleteUser() {
		final String email = String.format("mrhat%d@fancypants.com", ++userCounter);

		assertFalse(userRemover.remove(123456));

		// Save additional user
		User u = generateUser();
		try {
			u = authStorage.saveUser(u.type, u.email, u.passwordHash, u.firstName, u.lastName);
		} catch (UserException e) {
			fail("Failed to save a user");
		}
		assertNotNull(u);

		assertTrue(userRemover.remove(u.id));
		assertNull(userLoaderById.load(u.id));
		assertFalse(userRemover.remove(u.id));
	}

	@Test
	public void emailVerificationCode() {
		final String email = String.format("mscrabtree%d@evil.com", ++userCounter);
		final String code = UUID.randomUUID().toString();

		User user = null;
		try {
			authStorage.saveUser(UserType.REGULAR, email, "random", "Miss", "Crabtree");
			user = authStorage.loadUser(email);
		} catch (UserException e) {
			fail("Failed to save a verification code");
		}
		assertNotNull(user);
		assertFalse(user.emailVerified);

		BiConsumer<String, String> codeSaver = (em, c) -> {
			try {
				authStorage.saveEmailVerificationCode(em, c);
			} catch (UserException e) {
				fail("Failed to save a verification code");
			}
		};
		Function<String, String> codeVerifier = c -> {
			String res = null;
			try {
				res = authStorage.verifyEmailByCode(c);
			} catch (UserException e) {
				fail("Failed to verify a verification code");
			}
			return res;
		};
		Function<String, String> emailGetter = c -> {
			String em = null;
			try {
				em = userService.getEmailByVerificationCode(c);
			} catch (UserException e) {
				fail("Failed to get a verification code record");
			}
			return em;
		};
		Function<String, User> userGetter = em -> {
			User u = null;
			try {
				u = authStorage.loadUser(em);
			} catch (UserException e) {
				fail("Failed to get a user by email");
			}
			return u;
		};

		assertNull(codeVerifier.apply(code));

		codeSaver.accept(email, code);
		assertEquals(email, emailGetter.apply(code));

		assertEquals(email, codeVerifier.apply(code));
		assertTrue(userGetter.apply(email).emailVerified);

		assertNull(codeVerifier.apply(code));
	}

	@Parameterized.Parameters(name = "{0}")
	public static Collection instancesToTest() {
		SessionService sessionService = new MockSessionService(userService, testClient,
				Utilities.createTestTokensLifeTime());

		return Arrays.asList(new Object[][]{
				{DbAuthStorage.class.getSimpleName(), new DbAuthStorage(sessionService, userService)},
				{CachingAuthStorage.class.getSimpleName(), new CachingAuthStorage(new DbAuthStorage(sessionService, userService),
						new LRUStorageCache(1000*1000, 1000))}
		});
	}
}