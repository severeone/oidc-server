package severeone.oidc.auth.health;

import severeone.oidc.auth.db.users.UserException;
import severeone.oidc.auth.db.users.UserService;
import com.codahale.metrics.health.HealthCheck;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DatabaseHealthCheck extends HealthCheck {

	private static final Logger LOGGER = LoggerFactory.getLogger(DatabaseHealthCheck.class);
	private final UserService userService;
	private final String databaseUrl;

	public DatabaseHealthCheck(UserService userService, String databaseUrl) {
		this.userService = userService;
		this.databaseUrl = databaseUrl;
	}

	@Override
	protected Result check() throws Exception {
		try {
			userService.getUserById(1);
		} catch (UserException e) {
			LOGGER.error("\"Cannot connect to \" + databaseUrl. Error: " + e.getMessage());
			return Result.unhealthy("Cannot connect to " + databaseUrl);
		}
		return Result.healthy();
	}
}
