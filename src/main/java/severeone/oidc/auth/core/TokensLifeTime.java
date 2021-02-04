package severeone.oidc.auth.core;

import java.beans.ConstructorProperties;
import java.time.Duration;

public class TokensLifeTime {

	public UserType userType;
	public String clientId;
	public Duration accessTokenLifeTime;
	public Duration authorizationCodeLifeTime;

	@ConstructorProperties({"user_type", "client_id", "access_token_life_time", "auth_code_life_time"})
	public TokensLifeTime(int userType, String clientId, long accessTokenLifeTime, long authorizationCodeLifeTime) {
		this.userType = UserType.values()[userType];
		this.clientId = clientId;
		this.accessTokenLifeTime = Duration.ofSeconds(accessTokenLifeTime);
		this.authorizationCodeLifeTime = Duration.ofSeconds(authorizationCodeLifeTime);
	}

	public TokensLifeTime(UserType userType, String clientId, long accessTokenLifeTime, long authorizationCodeLifeTime) {
		this.userType = userType;
		this.clientId = clientId;
		this.accessTokenLifeTime = Duration.ofSeconds(accessTokenLifeTime);
		this.authorizationCodeLifeTime = Duration.ofSeconds(authorizationCodeLifeTime);
	}

	public TokensLifeTime(TokensLifeTime other) {
		this.userType = other.userType;
		this.clientId = other.clientId;
		this.accessTokenLifeTime = Duration.ofSeconds(other.accessTokenLifeTime.getSeconds());
		this.authorizationCodeLifeTime = Duration.ofSeconds(other.authorizationCodeLifeTime.getSeconds());
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		TokensLifeTime other = (TokensLifeTime) o;
		return userType == other.userType &&
				clientId.equals(other.clientId) &&
				accessTokenLifeTime.equals(other.accessTokenLifeTime) &&
				authorizationCodeLifeTime.equals(other.authorizationCodeLifeTime);
	}
}
