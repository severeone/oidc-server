package severeone.oidc.auth.core;

import java.beans.ConstructorProperties;
import java.net.MalformedURLException;
import java.net.URL;
import java.sql.Time;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.function.Supplier;

// Authorization session
public class Session {

	public String authorizationCode;
	public String clientId;
	public int userId;
	public Timestamp validTill;
	public URL redirectUri;
	public String nonce;

	private static Supplier<Instant> now = Instant::now;

	@ConstructorProperties({"code", "client_id", "user_id", "valid_till", "redirect_uri", "nonce"})
	public Session(String authorizationCode, String clientId, int userId, Timestamp validTill, String redirectUri,
	               String nonce) {
		this.authorizationCode = authorizationCode;
		this.clientId = clientId;
		this.userId = userId;
		this.validTill = validTill;
		try {
			this.redirectUri = new URL(redirectUri);
		} catch (MalformedURLException e) {
			e.printStackTrace();
		}
		this.nonce = nonce;
	}

	public Session(String authorizationCode, String clientId, int userId, Timestamp validTill, URL redirectUri,
	               String nonce) {
		this.authorizationCode = authorizationCode;
		this.clientId = clientId;
		this.userId = userId;
		this.validTill = validTill;
		this.redirectUri = redirectUri;
		this.nonce = nonce;
	}

	public Session(Session other) {
		this.authorizationCode = other.authorizationCode;
		this.clientId = other.clientId;
		this.userId = other.userId;
		this.validTill = other.validTill;
		try {
			this.redirectUri = new URL(other.redirectUri.toString());
		} catch (MalformedURLException e) {
			e.printStackTrace();
		}
		this.nonce = other.nonce;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		Session other = (Session) o;
		return authorizationCode.equals(other.authorizationCode) &&
				clientId.equals(other.clientId) &&
				userId == other.userId &&
				validTill.equals(other.validTill) &&
				redirectUri.equals(other.redirectUri) &&
				nonce.equals(other.nonce);
	}

	public boolean isExpired() {
		return validTill.before(Timestamp.from(now.get()));
	}

	public static void setNow(final Supplier<Instant> customNow) {
		now = customNow;
	}
}
