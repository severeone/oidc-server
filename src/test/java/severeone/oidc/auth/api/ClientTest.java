package severeone.oidc.auth.api;

import severeone.oidc.auth.core.Client;
import severeone.oidc.auth.util.Utilities;
import org.junit.Test;

import static org.junit.Assert.*;

public class ClientTest {
	@Test
	public void redirectUris() {
		Client c = Utilities.createTestClient();

		assertTrue(c.containsRedirectUri(Utilities.REDIRECT_URI_0));
		assertTrue(c.containsRedirectUri(Utilities.REDIRECT_URI_1));
		assertTrue(c.containsRedirectUri(Utilities.REDIRECT_URI_2));
	}
}