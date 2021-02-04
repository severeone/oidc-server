package severeone.oidc.auth.health;

import com.codahale.metrics.health.HealthCheck;

public class AuthHealthCheck extends HealthCheck {

	@Override
	protected Result check() throws Exception {
		return Result.healthy("OK");
	}
}
