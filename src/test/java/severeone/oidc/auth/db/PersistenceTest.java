package severeone.oidc.auth.db;

import severeone.oidc.auth.AuthApp;
import severeone.oidc.auth.AuthConfig;
import severeone.oidc.auth.core.*;
import severeone.oidc.auth.db.sessions.*;
import severeone.oidc.auth.tokens.gen.UUIDTokenGenerator;
import severeone.oidc.auth.util.Utilities;

import severeone.oidc.auth.db.users.*;
import io.dropwizard.jdbi3.JdbiFactory;
import io.dropwizard.testing.ResourceHelpers;
import io.dropwizard.testing.junit.DropwizardAppRule;

import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.sqlobject.SqlObjectPlugin;

import org.junit.After;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;

import java.net.MalformedURLException;
import java.net.URL;
import java.sql.Timestamp;
import java.util.Set;
import java.util.UUID;

import static com.shazam.shazamcrest.matcher.Matchers.sameBeanAs;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.junit.Assert.*;

public class PersistenceTest {

	private static Jdbi jdbi;
	private static Client testClient;
	private static TokensLifeTime testTokensLifeTime;

	@ClassRule
	public static final DropwizardAppRule<AuthConfig> RULE =
			new DropwizardAppRule<>(AuthApp.class, ResourceHelpers.resourceFilePath("config_for_test.yml"));

	@Test
	public void createUser() {
		UserService userService = createUserService();

		User u = null;
		try {
			u = userService.createUser(UserType.INVALID, "jdoe@me.com", "jdoepwd", "John", "Doe");
		} catch (UserException e) {
			assertThat(e, instanceOf(NoSuchUserTypeException.class));
		}
		assertNull(u);

		try {
			u = userService.createUser(UserType.REGULAR,"", "jdoepwd", "John", "Doe");
		} catch (UserException e) {
			assertThat(e, instanceOf(IncompleteUserException.class));
		}
		assertNull(u);

		try {
			u = userService.createUser(UserType.REGULAR,"jdoe@me.com", "", "John", "Doe");
		} catch (UserException e) {
			assertThat(e, instanceOf(IncompleteUserException.class));
		}
		assertNull(u);

		try {
			u = userService.createUser(UserType.REGULAR, "jdoe@me.com", "jdoepwd", "John", "Doe");
		} catch (UserException e) {
			fail("Failed to create a new user. " + e.getMessage());
		}
		assertNotNull(u);
		assertTrue(u.id >= 0);
		assertEquals(UserType.REGULAR, u.type);
		assertEquals("jdoe@me.com", u.email);
		assertEquals("John", u.firstName);
		assertEquals("Doe", u.lastName);
		assertTrue(Utilities.verifyHash("jdoepwd", u.passwordHash));
		assertFalse(u.emailVerified);

		User other1 = null, other2 = null;
		try {
			other1 = userService.createUser(UserType.REGULAR, "jdoe@me.com", "pwd", "Randy", "Marsh");
			other2 = userService.createUser(UserType.REGULAR, "jdoe@me.com", "pword", "Leopold", "Stotch");
		} catch (UserException e) {
			fail("Failed to create a new user. " + e.getMessage());
		}
		assertNull(other1);
		assertNull(other2);
	}

	@Test
	public void getUserByEmail() {
		UserService s = createUserService();

		User u = null;
		try {
			u = s.createUser(UserType.REGULAR, "jdoe@me.com", "jdoepwd", "John", "Doe");
		} catch (UserException e) {
			fail("Failed to create a new user. " + e.getMessage());
		}

		User actual = null;
		try {
			actual = s.getUserByEmail(u.email);
		} catch (UserException e) {
			fail("Failed to get user by email. " + e.getMessage());
		}
		assertThat(actual, sameBeanAs(u));

		try {
			actual = s.getUserByEmail("jdoe11111@me.com");
		} catch (UserException e) {
			fail("Failed to get user by email. " + e.getMessage());
		}
		assertNull(actual);
	}

	@Test
	public void getUserById() {
		UserService s = createUserService();

		User u = null;
		try {
			u = s.createUser(UserType.REGULAR, "jdoe@me.com", "jdoepwd", "John", "Doe");
		} catch (UserException e) {
			fail("Failed to create a new user. " + e.getMessage());
		}

		User actual = null;
		try {
			actual = s.getUserById(u.id);
		} catch (UserException e) {
			fail("Failed to get user by ID. " + e.getMessage());
		}
		assertThat(actual, sameBeanAs(u));

		try {
			actual = s.getUserById(678);
		} catch (UserException e) {
			fail("Failed to get user by ID. " + e.getMessage());
		}
		assertNull(actual);
	}

	@Test
	public void updateUserInfo() {
		UserService s = createUserService();

		User u = null;
		try {
			u = s.createUser(UserType.REGULAR, "jdoe@me.com", "jdoepwd", "John", "Doe");
		} catch (UserException e) {
			fail("Failed to create a new user. " + e.getMessage());
		}

		try {
			s.updateUserInfo(678, "randy.marsh@me.com", "Randy", "Marsh");
		} catch (UserException e) {
			assertThat(e, instanceOf(NoSuchUserException.class));
		}

		User other = null;
		try {
			other = s.createUser(UserType.REGULAR, "randy.marsh@me.com", "crabpeople", "Randy", "Marsh");
		} catch (UserException e) {
			fail("Failed to create a new user. " + e.getMessage());
		}

		try {
			s.updateUserInfo(u.id, "randy.marsh@me.com", "Randy", "Marsh");
		} catch (UserException e) {
			assertThat(e, instanceOf(DuplicateUserException.class));
		}

		try {
			s.updateUserInfo(u.id, "", "Randy", "Marsh");
		} catch (UserException e) {
			assertThat(e, instanceOf(IncompleteUserException.class));
		}

		try {
			s.updateUserInfo(u.id, "jdoe@me.com", "Randy", "Marsh");
		} catch (UserException e) {
			fail("Failed to update user info. " + e.getMessage());
		}
		try {
			other = s.getUserById(u.id);
		} catch (UserException e) {
			fail("Failed to get user by ID. " + e.getMessage());
		}
		assertEquals(u.id, other.id);
		assertEquals(u.type, other.type);
		assertEquals(u.email, other.email);
		assertEquals("Randy", other.firstName);
		assertEquals("Marsh", other.lastName);
		assertEquals(u.passwordHash, other.passwordHash);
		assertEquals(u.emailVerified, other.emailVerified);
	}

	@Test
	public void setPassword() {
		UserService s = createUserService();

		User u = null;
		try {
			u = s.createUser(UserType.REGULAR, "jdoe@me.com", "jdoepwd", "John", "Doe");
		} catch (UserException e) {
			fail("Failed to create a new user. " + e.getMessage());
		}

		try {
			s.setPassword(678, "crabpeople");
		} catch (UserException e) {
			assertThat(e, instanceOf(NoSuchUserException.class));
		}

		try {
			s.setPassword(u.id, "");
		} catch (UserException e) {
			assertThat(e, instanceOf(IncompleteUserException.class));
		}

		try {
			s.setPassword(u.id, "crabpeople");
		} catch (UserException e) {
			fail("Failed to set a new password. " + e.getMessage());
		}
		User other = null;
		try {
			other = s.getUserById(u.id);
		} catch (UserException e) {
			fail("Failed to get user by ID. " + e.getMessage());
		}
		assertEquals(u.id, other.id);
		assertEquals(u.type, other.type);
		assertEquals(u.email, other.email);
		assertEquals(u.firstName, other.firstName);
		assertEquals(u.lastName, other.lastName);
		assertTrue(Utilities.verifyHash("crabpeople", other.passwordHash));
		assertEquals(u.emailVerified, other.emailVerified);
	}

	@Test
	public void emailVerified() {
		UserService s = createUserService();

		User u = null;
		try {
			u = s.createUser(UserType.REGULAR, "jdoe@me.com", "jdoepwd", "John", "Doe");
		} catch (UserException e) {
			fail("Failed to create a new user. " + e.getMessage());
		}

		try {
			s.emailVerified(678);
		} catch (UserException e) {
			assertThat(e, instanceOf(NoSuchUserException.class));
		}

		try {
			s.emailVerified(u.id);
		} catch (UserException e) {
			fail("Failed to set email verified. " + e.getMessage());
		}
		User other = null;
		try {
			other = s.getUserById(u.id);
		} catch (UserException e) {
			fail("Failed to get user by ID. " + e.getMessage());
		}
		assertEquals(u.id, other.id);
		assertEquals(u.type, other.type);
		assertEquals(u.email, other.email);
		assertEquals(u.firstName, other.firstName);
		assertEquals(u.lastName, other.lastName);
		assertEquals(u.passwordHash, other.passwordHash);
		assertTrue(other.emailVerified);
	}

	@Test
	public void updateUserType() {
		UserService s = createUserService();

		User u = null;
		try {
			u = s.createUser(UserType.REGULAR, "jdoe@me.com", "jdoepwd", "John", "Doe");
		} catch (UserException e) {
			fail("Failed to create a new user. " + e.getMessage());
		}

		try {
			s.updateUserType(u.id, UserType.INVALID);
		} catch (UserException e) {
			assertThat(e, instanceOf(NoSuchUserTypeException.class));
		}

		try {
			s.updateUserType(678, UserType.REGULAR);
		} catch (UserException e) {
			assertThat(e, instanceOf(NoSuchUserException.class));
		}

		try {
			s.updateUserType(u.id, UserType.ADMIN);
		} catch (UserException e) {
			fail("Failed to update a user type. " + e.getMessage());
		}
		User other = null;
		try {
			other = s.getUserById(u.id);
		} catch (UserException e) {
			fail("Failed to get user by ID. " + e.getMessage());
		}
		assertEquals(u.id, other.id);
		assertEquals(UserType.ADMIN, other.type);
		assertEquals(u.email, other.email);
		assertEquals(u.firstName, other.firstName);
		assertEquals(u.lastName, other.lastName);
		assertEquals(u.passwordHash, other.passwordHash);
		assertEquals(u.emailVerified, other.emailVerified);
	}

	@Test
	public void deleteUser() {
		UserService s = createUserService();

		User u = null;
		try {
			u = s.createUser(UserType.REGULAR, "jdoe@me.com", "jdoepwd", "John", "Doe");
		} catch (UserException e) {
			fail("Failed to create a new user. " + e.getMessage());
		}

		try {
			s.deleteUser(678);
		} catch (UserException e) {
			assertThat(e, instanceOf(NoSuchUserException.class));
		}

		try {
			s.deleteUser(u.id);
		} catch (UserException e) {
			fail("Failed to delete a user. " + e.getMessage());
		}
		User other = null;
		try {
			other = s.getUserById(u.id);
		} catch (UserException e) {
			fail("Failed to get user by ID. " + e.getMessage());
		}
		assertNull(other);
	}

	@Test
	public void getUserType() {
		UserService s = createUserService();

		String userTypeDescription = null;
		try {
			userTypeDescription = s.getUserType(UserType.INVALID);
		} catch (UserException e) {
			fail("Failed to get a user type. " + e.getMessage());
		}
		assertNull(userTypeDescription);

		try {
			userTypeDescription = s.getUserType(UserType.REGULAR);
		} catch (UserException e) {
			fail("Failed to get a user type. " + e.getMessage());
		}
		assertNotNull(userTypeDescription);
	}

	interface EmailGetter { String get(final UserService service, final String code); }
	interface CodeCreator { void create(final UserService service, final String email, final String code); }

	private EmailGetter emailGetter = (s, code) -> {
		String email = null;
		try {
			 email = s.getEmailByVerificationCode(code);
		} catch (UserException e) {
			fail("Failed to get a verification code record");
		}
		return email;
	};

	private CodeCreator codeCreator = (s, email, code) -> {
		try {
			s.createEmailVerificationCode(email, code);
		} catch (UserException e) {
			fail("Failed to create a verification code record");
		}
	};

	@Test
	public void createEmailVerificationCode() {
		UserService s = createUserService();

		final String email = "randy.marsh@me.com";
		final String code0 = UUID.randomUUID().toString();
		final String code1 = UUID.randomUUID().toString();

		codeCreator.create(s, email, code0);
		codeCreator.create(s, email, code1);

		assertEquals(email, emailGetter.get(s, code0));
		assertEquals(email, emailGetter.get(s, code1));
	}

	@Test
	public void getEmailByVerificationCode()  {
		UserService s = createUserService();

		final String email = "randy.marsh@me.com";
		final String code = UUID.randomUUID().toString();

		assertNull(emailGetter.get(s, code));
		codeCreator.create(s, email, code);
		assertEquals(email, emailGetter.get(s, code));
	}

	@Test
	public void deleteEmailVerificationCode()  {
		UserService s = createUserService();

		final String email = "randy.marsh@me.com";
		final String code = UUID.randomUUID().toString();

		try {
			s.deleteEmailVerificationCode(code);
		} catch (UserException e) {
			if (!(e instanceof NoSuchEmailVerificationCodeException))
				fail("Failed to delete a verification code record");
		}

		codeCreator.create(s, email, code);
		try {
			s.deleteEmailVerificationCode(code);
		} catch (UserException e) {
			fail("Failed to delete a verification code record");
		}
		try {
			s.deleteEmailVerificationCode(code);
		} catch (UserException e) {
			if (!(e instanceof NoSuchEmailVerificationCodeException))
				fail("Failed to delete a verification code record");
		}
	}

	@Test
	public void getClient() {
		UserService userService = createUserService();
		SessionService service = createSessionService(userService);

		Client c = null;
		try {
			c = service.getClient("mscrabtree");
		} catch (SessionException e) {
			fail("Failed to get client: " + e.getMessage());
		}
		assertNull(c);

		try {
			c = service.getClient(testClient.id);
		} catch (SessionException e) {
			fail("Failed to get client: " + e.getMessage());
		}
		assertNotNull(c);
		assertEquals(testClient.id, c.id);
		assertEquals(testClient.secretHash, c.secretHash);
		assertEquals(testClient.name, c.name);
		Set<URL> actualUris = c.redirectUris;
		Set<URL> expectedUris = testClient.redirectUris;
		assertEquals(expectedUris.size(), actualUris.size());
		for (URL u: actualUris)
			assertTrue(expectedUris.contains(u));
	}

	@Test
	public void createSession() {
		UserService userService = createUserService();
		SessionService sessionService = createSessionService(userService);

		final String authorizationCode = "authcode";
		final String nonce = "noncenoncenonce";
		final Timestamp validTill = new Timestamp(System.currentTimeMillis());

		Session s = null;
		try {
			s = sessionService.createSession(authorizationCode, testClient.id, 678,
					Utilities.REDIRECT_URI_1, nonce, validTill);
		} catch (UserException|SessionException e) {
			assertThat(e, instanceOf(NoSuchUserException.class));
		}
		assertNull(s);

		User u = null;
		try {
			u = userService.createUser(UserType.REGULAR, "jdoe@me.com", "jdoepwd", "John", "Doe");
		} catch (UserException e) {
			fail("Failed to create a new user. " + e.getMessage());
		}
		assertNotNull(u);

		try {
			s = sessionService.createSession(authorizationCode, "mscrabtree", u.id,
					Utilities.REDIRECT_URI_1, nonce, validTill);
		} catch (UserException|SessionException e) {
			assertThat(e, instanceOf(NoSuchClientException.class));
		}
		assertNull(s);

		try {
			s = sessionService.createSession("", testClient.id, u.id,
					Utilities.REDIRECT_URI_1, nonce, validTill);
		} catch (UserException|SessionException e) {
			assertThat(e, instanceOf(IncompleteSessionException.class));
		}
		assertNull(s);

		try {
			s = sessionService.createSession(authorizationCode, testClient.id, u.id,null,
					nonce, validTill);
		} catch (UserException|SessionException e) {
			assertThat(e, instanceOf(IncompleteSessionException.class));
		}
		assertNull(s);

		try {
			s = sessionService.createSession(authorizationCode, testClient.id, u.id,
					new URL("http://evil.com/"), nonce, validTill);
		} catch (UserException|SessionException|MalformedURLException e) {
			assertThat(e, instanceOf(InvalidRedirectUriException.class));
		}
		assertNull(s);

		try {
			s = sessionService.createSession(authorizationCode, testClient.id, u.id,
					Utilities.REDIRECT_URI_1, nonce, validTill);
		} catch (UserException|SessionException e) {
			fail("Failed to create a new session. " + e.getMessage());
		}
		assertNotNull(s);
		assertEquals(authorizationCode, s.authorizationCode);
		assertEquals(testClient.id, s.clientId);
		assertEquals(u.id, s.userId);
		assertEquals(Utilities.REDIRECT_URI_1, s.redirectUri);
		assertEquals(nonce, s.nonce);
		assertEquals(validTill, s.validTill);

		Session other1 = null, other2 = null;
		try {
			other1 = sessionService.createSession(authorizationCode, testClient.id, u.id,
					Utilities.REDIRECT_URI_0, "noncenonce", validTill);
			other2 = sessionService.createSession(authorizationCode, testClient.id, u.id,
					Utilities.REDIRECT_URI_2, "noncenoncenoncenonce", validTill);
		} catch (UserException|SessionException e) {
			fail("Failed to create a new session. " + e.getMessage());
		}
		assertThat(s, sameBeanAs(other1));
		assertThat(s, sameBeanAs(other2));
	}

	private Session prepareForSessionTesting(UserService userService, SessionService sessionService) {
		final String authorizationCode = "auth-code";
		final String nonce = "noncenoncenonce";
		final Timestamp validTill = new Timestamp(System.currentTimeMillis());

		User u = null;
		try {
			u = userService.createUser(UserType.REGULAR, "jdoe@me.com", "jdoepwd", "John", "Doe");
		} catch (UserException e) {
			fail("Failed to create a new user. " + e.getMessage());
		}
		assertNotNull(u);

		Session s = null;
		try {
			s = sessionService.createSession(authorizationCode, testClient.id, u.id,
					Utilities.REDIRECT_URI_1, nonce, validTill);
		} catch (UserException|SessionException e) {
			fail("Failed to create a new session. " + e.getMessage());
		}
		assertNotNull(s);

		return s;
	}

	@Test
	public void getSession() {
		UserService userService = createUserService();
		SessionService sessionService = createSessionService(userService);

		final Session s  = prepareForSessionTesting(userService, sessionService);

		Session actual = null;
		try {
			actual = sessionService.getSession(s.authorizationCode);
		} catch (SessionException e) {
			fail("Failed to get a session by authorization code. " + e.getMessage());
		}
		assertThat(actual, sameBeanAs(s));

		try {
			actual = sessionService.getSession("totalnonsense");
		} catch (SessionException e) {
			fail("Failed to get a session by authorization code. " + e.getMessage());
		}
		assertNull(actual);
	}

	@Test
	public void deleteSession() {
		UserService userService = createUserService();
		SessionService sessionService = createSessionService(userService);

		final Session s  = prepareForSessionTesting(userService, sessionService);

		try {
			sessionService.deleteSession("totalnonsense");
		} catch (SessionException e) {
			assertThat(e, instanceOf(NoSuchSessionException.class));
		}

		try {
			sessionService.deleteSession(s.authorizationCode);
		} catch (SessionException e) {
			fail("Failed to delete a session. " + e.getMessage());
		}
		Session other = null;
		try {
			other = sessionService.getSession(s.authorizationCode);
		} catch (SessionException e) {
			fail("Failed to get a session. " + e.getMessage());
		}
		assertNull(other);
	}

	@Test
	public void createTokensRecord() {
		UserService userService = createUserService();
		SessionService sessionService = createSessionService(userService);

		final String refreshToken = "refresh-token";
		final String encryptedAccessToken = "access-token-hash";

		User u = null;
		try {
			u = userService.createUser(UserType.REGULAR, "mscrabtree@evil.com", "manbearpig",
					"Miss", "Crabtree");
		} catch (UserException e) {
			fail("Failed to create a user. " + e.getMessage());
		}

		AccessData ad = null;
		try {
			ad = sessionService.createTokensRecord(refreshToken, encryptedAccessToken, "mscrabtree", u.id);
		} catch (SessionException e) {
			assertThat(e, instanceOf(NoSuchClientException.class));
		}
		assertNull(ad);

		try {
			ad = sessionService.createTokensRecord("", encryptedAccessToken, testClient.id, u.id);
		} catch (SessionException e) {
			assertThat(e, instanceOf(IncompleteTokensRecordException.class));
		}
		assertNull(ad);

		try {
			ad = sessionService.createTokensRecord(refreshToken, "", testClient.id, u.id);
		} catch (SessionException e) {
			assertThat(e, instanceOf(IncompleteTokensRecordException.class));
		}
		assertNull(ad);

		try {
			ad = sessionService.createTokensRecord(refreshToken, encryptedAccessToken, testClient.id, u.id);
		} catch (SessionException e) {
			fail("Failed to create a tokens record. " + e.getMessage());
		}
		assertNotNull(ad);
		assertEquals(refreshToken, ad.refreshToken);
		assertEquals(encryptedAccessToken, ad.encryptedAccessToken);
		assertEquals(testClient.id, ad.clientId);
		assertEquals(u.id, ad.userId);

		AccessData other = null;
		try {
			other = sessionService.createTokensRecord(refreshToken, "anothertoken", testClient.id, u.id);
		} catch (SessionException e) {
			assertThat(e, instanceOf(DuplicateTokenException.class));
		}
		assertNull(other);

		try {
			other = sessionService.createTokensRecord("anothertoken", encryptedAccessToken, testClient.id, u.id);
		} catch (SessionException e) {
			assertThat(e, instanceOf(DuplicateTokenException.class));
		}
		assertNull(other);
	}

	private AccessData prepareForTokensRecordTesting(SessionService sessionService,
													 UserService userService) {
		final String refreshToken = "refresh-token";
		final String encryptedAccessToken = "access-token-hash";

		User u = null;
		try {
			u = userService.createUser(UserType.REGULAR, "mscrabtree@evil.com", "manbearpig",
					"Miss", "Crabtree");
		} catch (UserException e) {
			fail("Failed to create a user. " + e.getMessage());
		}

		AccessData ad = null;
		try {
			ad = sessionService.createTokensRecord(refreshToken, encryptedAccessToken, testClient.id, u.id);
		} catch (SessionException e) {
			fail("Failed to create a tokens record. " + e.getMessage());
		}
		assertNotNull(ad);

		return ad;
	}

	@Test
	public void getTokensRecord() {
		UserService userService = createUserService();
		SessionService sessionService = createSessionService(userService);

		final AccessData ad = prepareForTokensRecordTesting(sessionService, userService);

		AccessData actual = null;
		try {
			actual = sessionService.getTokensRecord("totalnonsense");
		} catch (SessionException e) {
			fail("Failed to get a tokens record by a refresh token. " + e.getMessage());
		}
		assertNull(actual);

		try {
			actual = sessionService.getTokensRecord(ad.refreshToken);
		} catch (SessionException e) {
			fail("Failed to get a tokens record by a refresh token. " + e.getMessage());
		}
		assertThat(actual, sameBeanAs(ad));
	}

	@Test
	public void deleteTokensRecord() {
		UserService userService = createUserService();
		SessionService sessionService = createSessionService(userService);

		final AccessData ad = prepareForTokensRecordTesting(sessionService, userService);

		try {
			sessionService.deleteTokensRecord("totalnonsense");
		} catch (SessionException e) {
			assertThat(e, instanceOf(NoSuchTokenException.class));
		}

		try {
			sessionService.deleteTokensRecord(ad.encryptedAccessToken);
		} catch (SessionException e) {
			fail("Failed to delete a tokens record. " + e.getMessage());
		}
		AccessData other = null;
		try {
			other = sessionService.getTokensRecord(ad.encryptedAccessToken);
		} catch (SessionException e) {
			fail("Failed to get a tokens record. " + e.getMessage());
		}
		assertNull(other);
	}

	@Test
	public void getTokensLifeTime() {
		UserService userService = createUserService();
		SessionService service = createSessionService(userService);

		TokensLifeTime tlt = null;
		try {
			tlt = service.getTokensLifeTime(UserType.INVALID, testClient.id);
		} catch (UserException|SessionException e) {
			assertThat(e, instanceOf(NoSuchUserTypeException.class));
		}
		assertNull(tlt);

		try {
			tlt = service.getTokensLifeTime(UserType.REGULAR, "mscrabtree");
		} catch (UserException|SessionException e) {
			assertThat(e, instanceOf(NoSuchClientException.class));
		}
		assertNull(tlt);

		try {
			tlt = service.getTokensLifeTime(UserType.REGULAR, testClient.id);
		} catch (UserException|SessionException e) {
			fail("Failed to get tokens life time: " + e.getMessage());
		}
		assertNotNull(tlt);
		assertEquals(testTokensLifeTime.clientId, tlt.clientId);
		assertEquals(testTokensLifeTime.userType, tlt.userType);
		assertEquals(testTokensLifeTime.accessTokenLifeTime, tlt.accessTokenLifeTime);
		assertEquals(testTokensLifeTime.authorizationCodeLifeTime, tlt.authorizationCodeLifeTime);
	}

	@BeforeClass
	public static void setup() {
		testClient = Utilities.createTestClient();
		testTokensLifeTime = Utilities.createTestTokensLifeTime();

		if (!"1".equals(System.getenv("INTEGRATION"))) {
			System.out.println("Using mock services");
			return;
		}

		System.out.println("Using DAO services");
		System.out.println(RULE.getConfiguration().getDataSourceFactory().getUrl());
		try {
			RULE.getApplication().run("server", "config.yml");
		} catch (Exception e) {
			fail("Failed to start application: " + e.getMessage());
		}

		final JdbiFactory jdbiFactory = new JdbiFactory();
		jdbi = jdbiFactory.build(RULE.getEnvironment(),
				RULE.getConfiguration().getDataSourceFactory(), "postgresql");
		jdbi.installPlugin(new SqlObjectPlugin());

		// Initialize client tables for testing
		jdbi.withHandle(handle -> {
			handle.execute("DELETE FROM client_redirect_uris");
			handle.execute("DELETE FROM tokens_life_time");
			handle.execute("DELETE FROM clients");
			handle.createUpdate("INSERT INTO clients(id, secret, name) VALUES (:id, :secret, :name)")
					.bind("id", testClient.id)
					.bind("secret", testClient.secretHash)
					.bind("name", testClient.name)
					.execute();
			for (URL u : testClient.redirectUris)
				handle.createUpdate("INSERT INTO client_redirect_uris(id, redirect_uri) VALUES(:id, :uri)")
						.bind("id", testClient.id)
						.bind("uri", u.toString())
						.execute();
			handle.createUpdate(
					"INSERT INTO tokens_life_time(user_type, client_id, access_token_life_time, auth_code_life_time) " +
					"VALUES (:user_type, :client_id, :access_token_life_time, :auth_code_life_time)")
					.bind("user_type", testTokensLifeTime.userType.ordinal())
					.bind("client_id", testTokensLifeTime.clientId)
					.bind("access_token_life_time", testTokensLifeTime.accessTokenLifeTime.getSeconds())
					.bind("auth_code_life_time", testTokensLifeTime.authorizationCodeLifeTime.getSeconds())
					.execute();
			return null;
		});
	}

	@After
	public void clean() {
		if (!"1".equals(System.getenv("INTEGRATION"))) {
			return;
		}

		// Clean users and auth_sessions tables
		jdbi.withHandle(handle -> {
			handle.execute("DELETE FROM tokens");
			handle.execute("DELETE FROM auth_sessions");
			handle.execute("DELETE FROM users");
			return null;
		});
	}

	private UserService createUserService() {
    	String integration = System.getenv("INTEGRATION");

		if ("1".equals(integration)) {
			return new DaoUserService(jdbi);
		} else {
			return new MockUserService(UserType.values().length);
		}
	}

	private SessionService createSessionService(UserService userService) {
		String integration = System.getenv("INTEGRATION");

		if ("1".equals(integration)) {
			return new DaoSessionService(jdbi, userService);
		} else {
			return new MockSessionService((MockUserService)userService, testClient, testTokensLifeTime);
		}
	}
}