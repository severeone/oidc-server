package severeone.oidc.auth;

import severeone.oidc.auth.core.Client;
import severeone.oidc.auth.core.OAuthToken;
import severeone.oidc.auth.core.email.EmailServicesExtensionImpl;
import severeone.oidc.auth.core.storage.*;
import severeone.oidc.auth.db.sessions.DaoSessionService;
import severeone.oidc.auth.db.sessions.SessionService;
import severeone.oidc.auth.db.users.DaoUserService;
import severeone.oidc.auth.health.AuthHealthCheck;
import severeone.oidc.auth.health.DatabaseHealthCheck;
import severeone.oidc.auth.db.users.UserService;
import severeone.oidc.auth.util.resources.*;
import severeone.oidc.auth.resources.AuthService;
import severeone.email.EmailService;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;

import io.dropwizard.Application;
import io.dropwizard.auth.*;
import io.dropwizard.auth.basic.BasicCredentialAuthFilter;
import io.dropwizard.auth.basic.BasicCredentials;
import io.dropwizard.auth.oauth.OAuthCredentialAuthFilter;
import io.dropwizard.client.HttpClientBuilder;
import io.dropwizard.configuration.EnvironmentVariableSubstitutor;
import io.dropwizard.configuration.SubstitutingSourceProvider;
import io.dropwizard.jdbi3.JdbiFactory;
import io.dropwizard.jdbi3.bundles.JdbiExceptionsBundle;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;

import org.apache.http.impl.client.CloseableHttpClient;
import org.eclipse.jetty.servlets.CrossOriginFilter;

import org.glassfish.hk2.utilities.binding.AbstractBinder;

import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.sqlobject.SqlObjectPlugin;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.DispatcherType;
import javax.servlet.FilterRegistration;
import java.util.EnumSet;

public class AuthApp extends Application<AuthConfig> {

	private static final Logger LOGGER = LoggerFactory.getLogger(AuthApp.class);

	private EmailService srv = new EmailService(new EmailServicesExtensionImpl());

	public EmailService getEmailService() {
		return this.srv;
	}

	public static void main(String[] args) throws Exception {
		LOGGER.debug("Entering 'main'");
		new AuthApp().run(args);
	}

	@Override
	public void run(AuthConfig config, Environment env) {
		LOGGER.debug("Entering 'run'");
		setupCORS(env);

        // Database setup
        final JdbiFactory factory = new JdbiFactory();
		final Jdbi jdbi = factory.build(env, config.getDataSourceFactory(), "postgresql");
		jdbi.installPlugin(new SqlObjectPlugin());

		// Creating data services
		final UserService userService = new DaoUserService(jdbi);
		final SessionService sessionService = new DaoSessionService(jdbi, userService);
		final StorageCache storageCache = new LRUStorageCache(1000*1000, 1000);
		final AuthStorage authStorage = new CachingAuthStorage(
				new DbAuthStorage(sessionService, userService), storageCache);

		setupAuthentication(env, config, authStorage);

		// Resources and error mappers
		env.jersey().register(new AuthValueFactoryProvider.Binder<>(Client.class));
		env.jersey().register(new AuthJerseyViolationExceptionMapper());
		env.jersey().register(new AuthInternalServerErrorExceptionMapper());
		env.jersey().register(new CatchAllExceptionMapper());
//		env.jersey().register(new TestResource(getEmailService()));

		final AuthService authService = new AuthService(config, authStorage);
		final CloseableHttpClient httpClient = new HttpClientBuilder(env).using(config.getHttpClientConfiguration())
				.build("AuthServer");
		authService.setHttpClient(httpClient);
		env.jersey().register(authService);

        // Health checks
		env.healthChecks().register("auth-service", new AuthHealthCheck());
		env.healthChecks().register("database",
				new DatabaseHealthCheck(userService, config.getDataSourceFactory().getUrl()));
	}

	private void setupCORS(final Environment env) {
		// Enable CORS headers
		final FilterRegistration.Dynamic cors = env.servlets().addFilter("CORS", CrossOriginFilter.class);

		// Configure CORS parameters
		cors.setInitParameter(CrossOriginFilter.ACCESS_CONTROL_ALLOW_ORIGIN_HEADER, "*");
		cors.setInitParameter(CrossOriginFilter.ALLOWED_ORIGINS_PARAM, "*");
		cors.setInitParameter(CrossOriginFilter.ALLOWED_HEADERS_PARAM, "X-Requested-With,Content-Type,Accept,Origin");
		cors.setInitParameter(CrossOriginFilter.ALLOWED_METHODS_PARAM, "OPTIONS,GET,PUT,POST,DELETE,HEAD");

		// Add URL mapping
		cors.addMappingForUrlPatterns(EnumSet.allOf(DispatcherType.class), true, "/*");

		// DO NOT pass a preflight request to down-stream auth filters
		// unauthenticated preflight requests should be permitted by spec
		cors.setInitParameter(CrossOriginFilter.CHAIN_PREFLIGHT_PARAM, Boolean.FALSE.toString());
	}

	private void setupAuthentication(final Environment env, final AuthConfig config,
									 final AuthStorage authStorage) {
		// Basic Authentication
		final AuthFilter<BasicCredentials, Client> basicCredentialAuthFilter =
				new BasicCredentialAuthFilter.Builder<Client>()
						.setAuthenticator(new BasicAuthenticator(authStorage))
						.setRealm("OpenID Connect")
						.setPrefix("Basic")
						.setUnauthorizedHandler(new AuthTokenUnauthorizedHandler())
						.buildAuthFilter();

		// OAuth2
		final AuthFilter<String, OAuthToken> oauthCredentialAuthFilter =
				new OAuthCredentialAuthFilter.Builder<OAuthToken>()
						.setAuthenticator(new OAuthAuthenticator(config, authStorage))
						.setRealm("OpenID Connect")
						.setPrefix("Bearer")
						.setUnauthorizedHandler(new AuthTokenUnauthorizedHandler())
						.buildAuthFilter();

		final PolymorphicAuthDynamicFeature feature = new PolymorphicAuthDynamicFeature<>(
				ImmutableMap.of(
						Client.class, basicCredentialAuthFilter,
						OAuthToken.class, oauthCredentialAuthFilter));
		final AbstractBinder binder = new PolymorphicAuthValueFactoryProvider.Binder<>(
				ImmutableSet.of(Client.class, OAuthToken.class));

		env.jersey().register(feature);
		env.jersey().register(binder);
	}

	// we don't want Dropwizard to override our logback config
	@Override
	protected void bootstrapLogging() {
	}

	@Override
	public void initialize(Bootstrap<AuthConfig> bootstrap) {
		LOGGER.debug("Entering 'initialize'");
		bootstrap.setConfigurationSourceProvider(new SubstitutingSourceProvider(
				bootstrap.getConfigurationSourceProvider(),
				new EnvironmentVariableSubstitutor(false)));
		bootstrap.addBundle(new JdbiExceptionsBundle());
	}
}
