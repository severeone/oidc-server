package severeone.oidc.auth.core.storage;

import severeone.oidc.auth.core.*;
import severeone.oidc.auth.db.sessions.MockSessionService;
import severeone.oidc.auth.db.sessions.SessionException;
import severeone.oidc.auth.db.sessions.SessionService;
import severeone.oidc.auth.db.users.MockUserService;
import severeone.oidc.auth.db.users.UserException;
import severeone.oidc.auth.db.users.UserService;
import severeone.oidc.auth.util.Utilities;

import org.junit.Test;

import java.net.URL;
import java.sql.Timestamp;
import java.time.Instant;

import static com.shazam.shazamcrest.matcher.Matchers.sameBeanAs;

import static org.junit.Assert.*;

public class CachingAuthStorageTest {

	class OpCount {

		int save, load, remove;

		OpCount(int save, int load, int remove) {
			this.save = save;
			this.load = load;
			this.remove = remove;
		}
	}

	class CountingAuthStorage implements AuthStorage {

		private AuthStorage storage;

		OpCount authorization = new OpCount(0 ,0 ,0);
		OpCount access = new OpCount(0, 0, 0);

		CountingAuthStorage(AuthStorage storage) {
			this.storage = storage;
		}

		@Override
		public Session saveAuthorizationData(String authorizationCode, String clientId, int userId, URL redirectUri,
                                             String nonce, Timestamp validTill) throws UserException, SessionException {
			++authorization.save;
			return storage.saveAuthorizationData(authorizationCode, clientId, userId, redirectUri, nonce, validTill);
		}

		@Override
		public Session loadAuthorizationData(String authorizationCode) throws SessionException {
			++authorization.load;
			return storage.loadAuthorizationData(authorizationCode);
		}

		@Override
		public boolean removeAuthorizationData(String authorizationCode) throws SessionException {
			++authorization.remove;
			return storage.removeAuthorizationData(authorizationCode);
		}

		@Override
		public AccessData saveAccessData(String refreshToken, String accessTokenHash, String clientId, int userId)
				throws SessionException {
			++access.save;
			return storage.saveAccessData(refreshToken, accessTokenHash, clientId, userId);
		}

		@Override
		public AccessData loadAccessData(String refreshToken) throws SessionException {
			++access.load;
			return storage.loadAccessData(refreshToken);
		}

		@Override
		public boolean removeAccessData(String accessTokenHash) throws SessionException {
			++access.remove;
			return storage.removeAccessData(accessTokenHash);
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
		public void updateUser(int id, String email, String firstName, String lastName, String password,
		                       UserType userType) throws UserException {
			storage.updateUser(id, email, firstName, lastName, password, userType);
		}

		@Override
		public boolean deleteUser(int id) throws UserException {
			return storage.deleteUser(id);
		}

		@Override
		public void saveEmailVerificationCode(String email, String code) throws UserException {
			storage.saveEmailVerificationCode(email,code);
		}

		@Override
		public String verifyEmailByCode(String code) throws UserException {
			return storage.verifyEmailByCode(code);
		}
	}

	class CachingAuthStorageTestContext {
		UserService userService;
		SessionService sessionService;
		AuthStorage storage;

		User user;

		// innerCounter wraps storage directly
		CountingAuthStorage innerCounter;
		// outerCounter wraps the caching layer around storage
		CountingAuthStorage outerCounter;

		// now points to the artificially controlled test time.
		Instant now;

		CachingAuthStorageTestContext() {
			userService = new MockUserService(1);
			sessionService = new MockSessionService((MockUserService)userService, Utilities.createTestClient(),
					Utilities.createTestTokensLifeTime());
			storage = new DbAuthStorage(sessionService, userService);

			// set up a test user
			try {
				user = userService.createUser(UserType.REGULAR, "rmarsh@me.com", "lorde", "Randy", "Marsh");
			} catch (UserException e) {
				fail("Failed to create a test user: " + e.getMessage());
			}

			// Set up a caching storage with inner and outer counters.
			now = Instant.now();
			innerCounter = new CountingAuthStorage(storage);
			outerCounter = new CountingAuthStorage(
					new CachingAuthStorage(
							innerCounter, new LRUStorageCache(1 << 20, 60, () -> now)
					)
			);
		}

		void advance(long durationSeconds) {
			now = now.plusSeconds(durationSeconds);
		}
	}

	interface DataLoader<T> { T load(AuthStorage storage, String key); }
	interface DataSaver<T> { T save(AuthStorage storage, T value); }
	interface DataRemover { boolean remove(AuthStorage storage, String key); }

	private DataLoader<Session> authLoader = (storage, authCode) -> {
		Session actual = null;
		try {
			actual = storage.loadAuthorizationData(authCode);
		} catch (SessionException e) {
			fail("Failed to load authorization data: " + e.getMessage());
		}
		return actual;
	};

	private DataLoader<AccessData> accessLoader = (storage, refreshToken) -> {
		AccessData actual = null;
		try {
			actual = storage.loadAccessData(refreshToken);
		} catch (SessionException e) {
			fail("Failed to load access data: " + e.getMessage());
		}
		return actual;
	};

	private DataSaver<Session> authSaver = (storage, session) -> {
		Session actual = null;
		try {
			actual = storage.saveAuthorizationData(session.authorizationCode, session.clientId, session.userId,
					session.redirectUri, session.nonce, session.validTill);
		} catch (SessionException|UserException e) {
			fail("Failed to save authorization data: " + e.getMessage());
		}
		return actual;
	};

	private DataSaver<AccessData> accessSaver = (storage, ad) -> {
		AccessData actual = null;
		try {
			actual = storage.saveAccessData(ad.refreshToken, ad.encryptedAccessToken, ad.clientId, ad.userId);
		} catch (SessionException e) {
			fail("Failed to save access data: " + e.getMessage());
		}
		return actual;
	};

	private DataRemover authRemover = (storage, authCode) -> {
		boolean res = false;
		try {
			res = storage.removeAuthorizationData(authCode);
		} catch (SessionException e) {
			fail("Failed to remove authorization data: " + e.getMessage());
		}
		return res;
	};

	private DataRemover accessRemover = (storage, ath) -> {
		boolean res = false;
		try {
			res = storage.removeAccessData(ath);
		} catch (SessionException e) {
			fail("Failed to remove access data: " + e.getMessage());
		}
		return res;
	};

	@Test
	public void testCachingStorageLoadsFailOnEmpty() {
		CachingAuthStorageTestContext ctx = new CachingAuthStorageTestContext();

		assertNull(authLoader.load(ctx.outerCounter, "totalnonsense"));
		assertThat("after one loadAuthorizationData",
				ctx.outerCounter.authorization, sameBeanAs(new OpCount(0, 1, 0)));
		assertThat("passthrough on first loadAuthorizationData",
				ctx.innerCounter.authorization, sameBeanAs(ctx.outerCounter.authorization));

		assertNull(accessLoader.load(ctx.outerCounter, "totalnonsense"));
		assertThat("after one loadAccessData",
				ctx.outerCounter.access, sameBeanAs(new OpCount(0, 1, 0)));
		assertThat("passthrough on first loadAccessData",
				ctx.innerCounter.access, sameBeanAs(ctx.outerCounter.access));
	}

	@Test
	public void testCachingAuthStorageAuthorizationOps() {
		CachingAuthStorageTestContext ctx = new CachingAuthStorageTestContext();

		Session saved = new Session(
				"auth-code",
				Utilities.CLIENT_ID,
				ctx.user.id,
				Timestamp.from(Instant.now().plusSeconds(300)),
				Utilities.REDIRECT_URI_0,
				"noncenonce"
		);
		assertNotNull(authSaver.save(ctx.outerCounter, saved));

		// Load the value saved above.
		ctx.advance(10);
		Session loaded = authLoader.load(ctx.outerCounter, saved.authorizationCode);
		assertThat("1st loadAuthorizationData", saved, sameBeanAs(loaded));
		assertThat("after an authorization save/load",
				ctx.outerCounter.authorization, sameBeanAs(new OpCount(1, 1, 0)));
		assertThat("passthrough after an authorization save/load (should be cached)",
				ctx.innerCounter.authorization, sameBeanAs(new OpCount(1, 0, 0)));

		// Advance within the cache expiry interval & try again.
		ctx.advance(10);
		loaded = authLoader.load(ctx.outerCounter, saved.authorizationCode);
		assertThat("another loadAuthorizationData", saved, sameBeanAs(loaded));
		assertThat("after another authorization save/load",
				ctx.outerCounter.authorization, sameBeanAs(new OpCount(1, 2, 0)));
		assertThat("passthrough after another authorization save/load (should be cached)",
				ctx.innerCounter.authorization, sameBeanAs(new OpCount(1, 0, 0)));

		// Advance past the cache expiry interval & try again.
		ctx.advance(60);
		loaded = authLoader.load(ctx.outerCounter, saved.authorizationCode);
		assertThat("3rd loadAuthorizationData", saved, sameBeanAs(loaded));
		assertThat("after 3rd authorization save/load",
				ctx.outerCounter.authorization, sameBeanAs(new OpCount(1, 3, 0)));
		assertThat("passthrough after 3rd authorization save/load (should be cached)",
				ctx.innerCounter.authorization, sameBeanAs(new OpCount(1, 1, 0)));

		// Remove the value explicitly, then check that it was removed.
		assertTrue(authRemover.remove(ctx.outerCounter, saved.authorizationCode));
		assertNull(authLoader.load(ctx.outerCounter, saved.authorizationCode));
		assertThat("after authorization remove/load",
				ctx.outerCounter.authorization, sameBeanAs(new OpCount(1, 4, 1)));
		assertThat("passthrough after authorization remove/load",
				ctx.innerCounter.authorization, sameBeanAs(new OpCount(1, 2, 1)));

		// Add again, then try advancing time past the invalidation interval.
		saved = new Session(
				"another-auth-code",
				Utilities.CLIENT_ID,
				ctx.user.id,
				Timestamp.from(Instant.now().plusSeconds(300)),
				Utilities.REDIRECT_URI_0,
				"noncenonce"
		);
		assertNotNull(authSaver.save(ctx.outerCounter, saved));
		ctx.advance(600);
		loaded = authLoader.load(ctx.outerCounter, saved.authorizationCode);
		assertThat("after invalidation interval", saved, sameBeanAs(loaded));
		assertThat("load after invalidation interval",
				ctx.outerCounter.authorization, sameBeanAs(new OpCount(2, 5, 1)));
		assertThat("passthrough load after invalidation interval",
				ctx.innerCounter.authorization, sameBeanAs(new OpCount(2, 3, 1)));
	}

	@Test
	public void testCachingAuthStorageAccessOps() {
		CachingAuthStorageTestContext ctx = new CachingAuthStorageTestContext();

		int userId = 123;
		AccessData saved = new AccessData(
				"refresh-token",
				"access-token-hash",
				Utilities.CLIENT_ID,
				userId
		);
		assertNotNull(accessSaver.save(ctx.outerCounter, saved));

		// Load the value once. Should be cached from save.
		ctx.advance(10);
		AccessData loaded = accessLoader.load(ctx.outerCounter, saved.refreshToken);
		assertThat("1st loadAccessData", saved, sameBeanAs(loaded));
		assertThat("after an access save/load",
				ctx.outerCounter.access, sameBeanAs(new OpCount(1, 1, 0)));
		assertThat("passthrough after an access save/load (should be cached)",
				ctx.innerCounter.access, sameBeanAs(new OpCount(1, 0, 0)));

		// Advance past the cache expiry interval & try again.
		ctx.advance(120);
		loaded = accessLoader.load(ctx.outerCounter, saved.refreshToken);
		assertThat("2nd loadAccessData", saved, sameBeanAs(loaded));
		assertThat("after 2nd access save/load",
				ctx.outerCounter.access, sameBeanAs(new OpCount(1, 2, 0)));
		assertThat("passthrough after 2nd access save/load (should be cached)",
				ctx.innerCounter.access, sameBeanAs(new OpCount(1, 1, 0)));

		// Save value again, then advance past invalidation interval
		saved = new AccessData(
				"another-refresh-token",
				"another-access-token-hash",
				Utilities.CLIENT_ID,
				userId
		);
		assertNotNull(accessSaver.save(ctx.outerCounter, saved));
		ctx.advance(400);
		loaded = accessLoader.load(ctx.outerCounter, saved.refreshToken);
		assertThat("loadAccessData after 2nd access save", saved, sameBeanAs(loaded));
		assertThat("loadAccessData after 2nd access save",
				ctx.outerCounter.access, sameBeanAs(new OpCount(2, 3, 0)));
		assertThat("passthrough loadAccessData after 2nd access save",
				ctx.innerCounter.access, sameBeanAs(new OpCount(2, 2, 0)));

		// Save value yet again, then explicitly remove and load
		saved = new AccessData(
				"3rd-refresh-token",
				"3rd-access-token-hash",
				Utilities.CLIENT_ID,
				userId
		);
		assertNotNull(accessSaver.save(ctx.outerCounter, saved));
		assertTrue(accessRemover.remove(ctx.outerCounter, saved.encryptedAccessToken));
		accessLoader.load(ctx.outerCounter, saved.refreshToken);
		assertThat("loadAccessData after remove",
				ctx.outerCounter.access, sameBeanAs(new OpCount(3, 4, 1)));
		assertThat("passthrough loadAccessData after remove",
				ctx.innerCounter.access, sameBeanAs(new OpCount(3, 3, 1)));
	}
}