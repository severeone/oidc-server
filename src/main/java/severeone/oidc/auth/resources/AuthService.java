package severeone.oidc.auth.resources;

import severeone.oidc.auth.AuthConfig;
import severeone.oidc.auth.core.Client;
import severeone.oidc.auth.core.OAuthToken;
import severeone.oidc.auth.core.UpdateUserJson;
import severeone.oidc.auth.core.UserType;
import severeone.oidc.auth.core.storage.AuthStorage;
import severeone.oidc.auth.util.resources.process.*;

import io.dropwizard.auth.Auth;
import io.dropwizard.jersey.params.NonEmptyStringParam;

import org.apache.http.impl.client.CloseableHttpClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.security.PermitAll;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

@Path("/auth")
@Produces(MediaType.APPLICATION_FORM_URLENCODED)
@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
public class AuthService {

	private static final Logger LOGGER = LoggerFactory.getLogger(AuthService.class);

	public static final String REDIRECT_URI = "redirect_uri";
    public static final String STATE = "state";
    public static final String EMAIL = "email";
    public static final String PASSWORD = "password";
    public static final String RESPONSE_TYPE = "response_type";
    public static final String SCOPE = "scope";
    public static final String CLIENT_ID = "client_id";
    public static final String ID_TOKEN_HINT = "id_token_hint";
    public static final String NONCE = "nonce";
    public static final String AUTHORIZATION_CODE = "code";
	public static final String CONFIRMATION_CODE = "code";
	public static final String GRANT_TYPE = "grant_type";
	public static final String ACCESS_TOKEN = "access_token";
	public static final String ADMIN_TOKEN = "admin_token";
	public static final String OPENID_PROVIDER_ORIGIN = "origin";
	public static final String ID_TOKEN = "id_token";
	public static final String TOKEN_TYPE = "token_type";
	public static final String EXPIRES_IN = "expires_in";
	public static final String REFRESH_TOKEN = "refresh_token";
	public static final String FIRST_NAME = "first_name";
	public static final String LAST_NAME = "last_name";
	public static final String USER_TYPE = "user_type";

	public static final String BEARER_TYPE = "Bearer";
	public static final String OPENID = "openid";
	public static final String AUTHORIZATION_CODE_GRANT = "authorization_code";
	public static final String REFRESH_TOKEN_GRANT = "refresh_token";

	public static final String CASE_BACKEND_CLIENT_ID = "oidc-backend";

	public static final UserType DEFAULT_USER_TYPE = UserType.REGULAR;

	private final AuthStorage authStorage;
	private final AuthConfig config;

	private CloseableHttpClient httpClient;

	public AuthService(final AuthConfig config, final AuthStorage authStorage) {
		this.authStorage = authStorage;
		this.config = config;
	}

	public void setHttpClient(final CloseableHttpClient httpClient) {
		this.httpClient = httpClient;
	}

	@POST
	@Path("/signup")
	@Produces(MediaType.APPLICATION_JSON)
	public Response signup(@FormParam(EMAIL) String email,
	                       @FormParam(PASSWORD) String password,
	                       @FormParam(FIRST_NAME) String firstName,
	                       @FormParam(LAST_NAME) String lastName) {

		LOGGER.debug(String.format("Entering 'signup': email=%s, password=%s, firstName=%s, lastName=%s", email, password, firstName, lastName));
        Response res = new SignupProcessor(config, authStorage)
                .userParams(email, password, firstName, lastName)
                .process();
        LOGGER.debug("Exiting 'signup' successfully");
        return res;
	}

	@POST
	@Path("/signon")
	@Produces(MediaType.APPLICATION_FORM_URLENCODED)
	public Response signon(@FormParam(EMAIL) NonEmptyStringParam email,
                           @FormParam(PASSWORD) NonEmptyStringParam password,
                           @FormParam(SCOPE) String scope,
                           @FormParam(RESPONSE_TYPE) String responseType,
                           @FormParam(REDIRECT_URI) String redirectUri,
                           @FormParam(CLIENT_ID) String clientId,
                           @FormParam(STATE) NonEmptyStringParam state,
                           @FormParam(NONCE) NonEmptyStringParam nonce) {

		LOGGER.debug(String.format("Entering 'signon': email=%s, password=%s, scope=%s, responseType=%s, redirectUri=%s, clientId=%s, state=%s, nonce=%s", email, password, scope, responseType, redirectUri, clientId, state, nonce));
        Response res = new AuthenticationProcessor(config, authStorage)
            .credentials(email.get().orElse(""), password.get().orElse(""))
            .oidc(AuthenticationProcessor.Mode.SIGNON, scope, responseType, redirectUri, clientId,
                    state.get().orElse(""), nonce.get().orElse(""))
            .process();
        LOGGER.debug("Exiting 'signon' successfully");
        return res;
	}

	@GET
	@Path("/authorize")
	@Produces(MediaType.APPLICATION_FORM_URLENCODED)
	public Response authorizeGet(@QueryParam(EMAIL) NonEmptyStringParam email,
	                             @QueryParam(PASSWORD) NonEmptyStringParam password,
	                             @QueryParam(SCOPE) String scope,
	                             @QueryParam(RESPONSE_TYPE) String responseType,
	                             @QueryParam(REDIRECT_URI)String redirectUri,
	                             @QueryParam(CLIENT_ID) String clientId,
	                             @QueryParam(STATE) NonEmptyStringParam state,
	                             @QueryParam(ID_TOKEN_HINT) NonEmptyStringParam idTokenHint,
	                             @QueryParam(NONCE) NonEmptyStringParam nonce) {

		LOGGER.debug(String.format("Entering 'authorizeGet': email=%s, password=%s, scope=%s, responseType=%s, redirectUri=%s, clientId=%s, state=%s, idTokenHint=%s, nonce=%s", email, password, scope, responseType, redirectUri, clientId, state, idTokenHint, nonce));
        Response res = new AuthenticationProcessor(config, authStorage)
            .credentials(email.get().orElse(""), password.get().orElse(""))
            .oidc(AuthenticationProcessor.Mode.AUTHORIZE, scope, responseType, redirectUri, clientId,
                    state.get().orElse(""), nonce.get().orElse(""))
            .idTokenHint(idTokenHint.get().orElse(""))
            .process();
        LOGGER.debug("Exiting 'authorizeGet' successfully");
        return res;
	}

	@POST
	@Path("/authorize")
	@Produces(MediaType.APPLICATION_FORM_URLENCODED)
	public Response authorizePost(@FormParam(EMAIL) NonEmptyStringParam email,
								  @FormParam(PASSWORD) NonEmptyStringParam password,
								  @FormParam(SCOPE) String scope,
								  @FormParam(RESPONSE_TYPE) String responseType,
								  @FormParam(REDIRECT_URI) String redirectUri,
								  @FormParam(CLIENT_ID) String clientId,
								  @FormParam(STATE) NonEmptyStringParam state,
								  @FormParam(ID_TOKEN_HINT) NonEmptyStringParam idTokenHint,
								  @FormParam(NONCE) NonEmptyStringParam nonce) {

		LOGGER.debug(String.format("Entering 'authorizePost': email=%s, password=%s, scope=%s, responseType=%s, redirectUri=%s, clientId=%s, state=%s, idTokenHint=%s, nonce=%s", email, password, scope, responseType, redirectUri, clientId, state, idTokenHint, nonce));
        Response res = new AuthenticationProcessor(config, authStorage)
            .credentials(email.get().orElse(""), password.get().orElse(""))
            .oidc(AuthenticationProcessor.Mode.AUTHORIZE, scope, responseType, redirectUri, clientId,
                    state.get().orElse(""), nonce.get().orElse(""))
            .idTokenHint(idTokenHint.get().orElse(""))
            .process();
        LOGGER.debug("Exiting 'authorizePost' successfully");
        return res;
	}

	@PermitAll
	@POST
	@Path("/token")
	@Produces(MediaType.APPLICATION_JSON)
	public Response token(@Auth Client client,
	                      @FormParam(GRANT_TYPE) String grantType,
	                      @FormParam(AUTHORIZATION_CODE) String authorizationCode,
	                      @FormParam(REDIRECT_URI) String redirectUri,
						  @FormParam(REFRESH_TOKEN) String refreshToken,
	                      @FormParam(SCOPE) String scope) {

		LOGGER.debug(String.format("Entering 'token': client=%s, grantType=%s, authorizationCode=%s, redirectUri=%s, refreshToken=%s, scope=%s", client, grantType, authorizationCode, redirectUri, refreshToken, scope));
        Response res = new TokenProcessor(config, authStorage)
            .authCodeFlow(authorizationCode, redirectUri)
            .refreshFlow(refreshToken, client.id, scope)
            .grant(grantType)
            .process();
        LOGGER.debug("Exiting 'token' successfully");
        return res;
	}

	@PermitAll
	@GET
	@Path("/userinfo")
	@Produces(MediaType.APPLICATION_JSON)
	public Response userInfoGet(@Auth OAuthToken oAuthToken) {

		LOGGER.debug(String.format("Entering 'userInfoGet': oAuthToken=%s", oAuthToken.getName()));
        Response res = new UserInfoProcessor(config, authStorage)
            .accessToken(oAuthToken.accessToken)
            .process();
        LOGGER.debug("Exiting 'userInfoGet' successfully");
        return res;
	}

	@PermitAll
	@POST
	@Path("/userinfo")
	@Produces(MediaType.APPLICATION_JSON)
	public Response userInfoPost(@Auth OAuthToken oAuthToken) {

		LOGGER.debug(String.format("Entering 'userInfoPost': oAuthToken=%s", oAuthToken.getName()));
        Response res = new UserInfoProcessor(config, authStorage)
            .accessToken(oAuthToken.accessToken)
            .process();
        LOGGER.debug("Exiting 'userInfoPost' successfully");
        return res;
	}

	@PermitAll
	@POST
	@Path("/revoke")
	@Produces(MediaType.APPLICATION_JSON)
	public Response revoke(@Auth Client client,
	                       @FormParam(ID_TOKEN) String idToken,
	                       @FormParam(ACCESS_TOKEN) String accessToken) {

		LOGGER.debug(String.format("Entering 'revoke': idToken=%s, accessToken=%s", idToken, accessToken));
        Response res = new RevokeProcessor(config, authStorage)
            .tokens(idToken, accessToken)
            .clientId(client.id)
            .process();
        LOGGER.debug("Exiting 'revoke' successfully");
        return res;
	}

	@PermitAll
	@POST
	@Path("/updusr")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response updateUser(@Auth Client client,
	                           UpdateUserJson updateUserJson) {

		LOGGER.debug(String.format("Entering 'updateUser': client=%s, updateUserJson=%s", client, updateUserJson));
        Response res = new UpdateUserProcessor(config, authStorage)
            .updateUserJson(updateUserJson)
            .clientId(client.id)
            .process();
        LOGGER.debug("Exiting 'updateUser' successfully");
        return res;
	}

	@PermitAll
	@POST
	@Path("/resetpwd")
	@Produces(MediaType.APPLICATION_JSON)
	public Response resetPassword(@Auth Client client,
	                              @FormParam(EMAIL) String email) {

		LOGGER.debug(String.format("Entering 'resetPassword': client=%s, email=%s", client, email));
		Response res = new ResetPasswordProcessor(config, authStorage)
				.email(email)
				.httpClient(httpClient)
				.process();
		LOGGER.debug("Exiting 'resetPassword' successfully");
		return res;
	}

	@POST
	@Path("/setnewpwd")
	@Produces(MediaType.APPLICATION_JSON)
	public Response setNewPassword(@FormParam(CONFIRMATION_CODE) String confirmationCode,
	                               @FormParam(PASSWORD) String password) {

        LOGGER.debug(String.format("Entering 'setNewPassword': confirmationCode=%s, password=%s",
		        confirmationCode, password));
		Response res =  new SetNewPasswordProcessor(config, authStorage)
				.code(confirmationCode)
				.password(password)
				.process();
        LOGGER.debug("Exiting 'setNewPassword' successfully");
        return res;
	}

	@GET
	@Path("/qa/delete_user")
	@Produces(MediaType.APPLICATION_JSON)
	public Response deleteUser(@QueryParam(EMAIL) String email,
	                           @QueryParam(ADMIN_TOKEN) String adminToken) {

		LOGGER.debug(String.format("Entering 'deleteUser': email=%s, adminToken=%s", email, adminToken));
		Response res =  new DeleteUserProcessor(config, authStorage)
				.email(email)
				.adminToken(adminToken)
				.process();
		LOGGER.debug("Exiting 'deleteUser' successfully");
		return res;
	}

	@POST
	@Path("/tmp/migrate_user")
	@Produces(MediaType.APPLICATION_JSON)
	public Response migrateUser(@FormParam(EMAIL) String email,
	                            @FormParam(FIRST_NAME) String firstName,
	                            @FormParam(LAST_NAME) String lastName) {

		LOGGER.debug(String.format("Entering 'migrateUser': email=%s, firstName=%s, lastName=%s", email, firstName, lastName));
		Response res = new MigrateProcessor(config, authStorage)
				.userParams(email, firstName, lastName)
				.process();
		LOGGER.debug("Exiting 'migrateUser' successfully");
		return res;
	}

	@GET
	@Path("/tmp/generate_reset_code")
	@Produces(MediaType.APPLICATION_JSON)
	public Response generateResetCode(@QueryParam(EMAIL) String email) {

		LOGGER.debug(String.format("Entering 'generateResetCode': email=%s", email));
		Response res = new GenerateResetCodeProcessor(config, authStorage)
				.email(email)
				.process();
		LOGGER.debug("Exiting 'generateResetCode' successfully");
		return res;
	}
}
