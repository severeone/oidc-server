package severeone.oidc.auth.util;

import severeone.oidc.auth.core.Client;
import severeone.oidc.auth.core.TokensLifeTime;
import severeone.oidc.auth.core.UserType;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.mindrot.jbcrypt.BCrypt;

import javax.ws.rs.InternalServerErrorException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.file.Files;
import java.nio.file.Paths;

public final class Utilities {

	public static URL REDIRECT_URI_0;
	public static URL REDIRECT_URI_1;
	public static URL REDIRECT_URI_2;
	public static String CLIENT_ID = "theclient";
	public static String CLIENT_SECRET = "clientsecret";

	static {
		try {
			REDIRECT_URI_0 = new URL("http://example.com/path0");
			REDIRECT_URI_1 = new URL("http://example.com/path1");
			REDIRECT_URI_2 = new URL("http://example.com/path2");
		} catch (MalformedURLException e) {
			e.printStackTrace();
		}
	}

	public static String hash(String password) {
		return BCrypt.hashpw(password, BCrypt.gensalt());
	}

	public static boolean verifyHash(String password, String hash) {
		return BCrypt.checkpw(password, hash);
	}

	public static Client createTestClient() {
		Client c = new Client(CLIENT_ID, "Super Important Client", Utilities.hash(CLIENT_SECRET));
		c.addRedirectUris(REDIRECT_URI_0);
		c.addRedirectUris(REDIRECT_URI_1);
		c.addRedirectUris(REDIRECT_URI_2);
		return c;
	}

	public static TokensLifeTime createTestTokensLifeTime() {
		return new TokensLifeTime(UserType.REGULAR, CLIENT_ID, 86400, 600);
	}

	public static String getToken(final String pathToToken) {
		String key;
		try {
			key = (new String(Files.readAllBytes(Paths.get(pathToToken)))).trim();
		} catch (IOException e) {
			throw new InternalServerErrorException("Failed to read a token: " + Paths.get(pathToToken));
		}
		return key;
	}

	public static String getVerificationEmail(final String pathToHtml) {
		String key;
		try {
			key = (new String(Files.readAllBytes(Paths.get(pathToHtml)))).trim();
		} catch (IOException e) {
			throw new InternalServerErrorException("Failed to read a verification email");
		}
		return key;
	}

	public static String escape(final String s) {
		if (s == null)
			return null;
		String escaped;
		try {
			escaped = URLEncoder.encode(s, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			// This should never happen
			e.printStackTrace();
			return null;
		}
		return escaped;
	}

	public static Throwable getRootCause(Throwable ex) {
		if (ex != null && ex.getCause() != null)
			return ExceptionUtils.getRootCause(ex);
		else
			return ex;
	}

	public static String getRootMessage(Throwable ex) {
		Throwable cause = getRootCause(ex);
		if (cause != null)
			return cause.getMessage();
		else
			return "no cause in :" + ex.getClass().getSimpleName();
	}
}
