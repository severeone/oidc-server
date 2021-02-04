package severeone.oidc.auth;

import com.fasterxml.jackson.annotation.JsonProperty;

import io.dropwizard.Configuration;
import io.dropwizard.client.HttpClientConfiguration;
import io.dropwizard.db.DataSourceFactory;
import io.dropwizard.util.Duration;
import io.dropwizard.validation.MinDuration;

import org.hibernate.validator.constraints.NotEmpty;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

import java.util.concurrent.TimeUnit;

public class AuthConfig extends Configuration {

	@NotEmpty
	private String integrationTestTargetUrl;

	@Valid
	@NotNull
	private DataSourceFactory database = new DataSourceFactory();

	@NotNull
	@MinDuration(value = 1, unit = TimeUnit.MINUTES)
	private Duration authCodeLifeTime = Duration.minutes(1);

	@NotNull
	@MinDuration(value = 1, unit = TimeUnit.HOURS)
	private Duration idTokenLifeTime = Duration.hours(1);

	@NotNull
	@MinDuration(value = 1, unit = TimeUnit.MINUTES)
	private Duration accessTokenLifeTime = Duration.minutes(1);

	@NotEmpty
	private String emailVerifiedPage;

	@NotEmpty
	private String confirmEmailPage;

	@NotEmpty
	private String loginPage;

	@NotEmpty
	private String signupCompletePage;

	@NotEmpty
	private String verificationEmailFilePath;

	@NotEmpty
	private String resetPasswordAPIEndpoint;

	@NotEmpty
	private String accessTokenKeyFilePath;

	@NotEmpty
	private String idTokenKeyFilePath;

	@NotEmpty
	private String adminTokenFilePath;

	@JsonProperty
	public HttpClientConfiguration getHttpClientConfiguration() {
		HttpClientConfiguration httpClientConfiguration = new HttpClientConfiguration();
		httpClientConfiguration.setConnectionTimeout(Duration.seconds(10));
		httpClientConfiguration.setConnectionRequestTimeout(Duration.seconds(10));
		httpClientConfiguration.setTimeout(Duration.seconds(10));
		return httpClientConfiguration;
	}

	@JsonProperty("resetPasswordAPIEndpoint")
	public String getResetPasswordAPIEndpoint() {
		return resetPasswordAPIEndpoint;
	}

	@JsonProperty("resetPasswordAPIEndpoint")
	public void setResetPasswordAPIEndpoint(String resetPasswordAPIEndpoint) {
		this.resetPasswordAPIEndpoint = resetPasswordAPIEndpoint;
	}

	@JsonProperty("confirmEmailPage")
	public String getConfirmEmailPage() {
		return confirmEmailPage;
	}

	@JsonProperty("confirmEmailPage")
	public void setConfirmEmailPage(String confirmEmailPage) {
		this.confirmEmailPage = confirmEmailPage;
	}

	@JsonProperty("emailVerifiedPage")
	public String getEmailVerifiedPage() {
		return emailVerifiedPage;
	}

	@JsonProperty("emailVerifiedPage")
	public void setEmailVerifiedPage(String emailVerifiedPage) {
		this.emailVerifiedPage = emailVerifiedPage;
	}

	@JsonProperty("loginPage")
	public String getLoginPage() {
		return loginPage;
	}

	@JsonProperty("loginPage")
	public void setLoginPage(final String loginPage) {
		this.loginPage = loginPage;
	}

	@JsonProperty("signupCompletePage")
	public String getSignupCompletePage() {
		return signupCompletePage;
	}

	@JsonProperty("signupCompletePage")
	public void setSignupCompletePage(final String signupCompletePage) {
		this.signupCompletePage = signupCompletePage;
	}

	@JsonProperty("database")
	public void setDataSourceFactory(DataSourceFactory factory) {
		this.database = factory;
	}

	@JsonProperty("database")
	public DataSourceFactory getDataSourceFactory() {
		return database;
	}

	@JsonProperty
	public Duration getAuthCodeLifeTime() {
		return authCodeLifeTime;
	}

	@JsonProperty
	public void setAuthCodeLifeTime(Duration time) {
		this.authCodeLifeTime = time;
	}

	@JsonProperty
	public String getIntegrationTestTargetUrl() {
		return integrationTestTargetUrl;
	}

	@JsonProperty
	public void setIntegrationTestTargetUrl(String url) {
		this.integrationTestTargetUrl = url;
	}

	@JsonProperty
	public Duration getIdTokenLifeTime() {
		return idTokenLifeTime;
	}

	@JsonProperty
	public void setIdTokenLifeTime(Duration idTokenLifeTime) {
		this.idTokenLifeTime = idTokenLifeTime;
	}

	@JsonProperty
	public Duration getAccessTokenLifeTime() {
		return accessTokenLifeTime;
	}

	@JsonProperty
	public void setAccessTokenLifeTime(Duration accessTokenLifeTime) {
		this.accessTokenLifeTime = accessTokenLifeTime;
	}

	@JsonProperty
	public String getVerificationEmailFilePath() {
		return verificationEmailFilePath;
	}

	@JsonProperty
	public void setVerificationEmailFilePath(String verificationEmailFilePath) {
		this.verificationEmailFilePath = verificationEmailFilePath;
	}

	@JsonProperty
	public String getAccessTokenKeyFilePath() {
		return accessTokenKeyFilePath;
	}

	@JsonProperty
	public void setAccessTokenKeyFilePath(String accessTokenKeyFilePath) {
		this.accessTokenKeyFilePath = accessTokenKeyFilePath;
	}

	@JsonProperty
	public String getIdTokenKeyFilePath() {
		return idTokenKeyFilePath;
	}

	@JsonProperty
	public void setIdTokenKeyFilePath(String idTokenKeyFilePath) {
		this.idTokenKeyFilePath = idTokenKeyFilePath;
	}

	@JsonProperty("adminTokenFilePath")
	public String getAdminTokenFilePath() {
		return adminTokenFilePath;
	}

	@JsonProperty("adminTokenFilePath")
	public void setAdminTokenFilePath(final String adminTokenFilePath) {
		this.adminTokenFilePath = adminTokenFilePath;
	}
}