package severeone.oidc.auth.core;

import severeone.oidc.auth.core.storage.AuthStorage;
import severeone.oidc.auth.db.sessions.SessionException;
import severeone.oidc.auth.resources.AuthService;
import severeone.oidc.auth.util.Utilities;
import severeone.oidc.auth.util.resources.AuthJerseyViolationException;
import severeone.oidc.auth.util.resources.AuthJerseyViolationExceptionMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.InternalServerErrorException;
import java.beans.ConstructorProperties;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.Principal;
import java.util.HashSet;
import java.util.Set;

public class Client implements Principal {

	private static final Logger LOGGER = LoggerFactory.getLogger(Client.class);
	public String id;
	public String name;
	public String secretHash;
	public Set<URL> redirectUris = new HashSet<>();

	@ConstructorProperties({"id", "name", "secret"})
	public Client(String id, String name, String secretHash) {
		this.id = id;
		this.name = name;
		this.secretHash = secretHash;
	}

	public Client(Client other) {
		this.id = other.id;
		this.name = other.name;
		this.secretHash = other.secretHash;
		this.redirectUris.addAll(other.redirectUris);
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		Client other = (Client) o;
		if (!id.equals(other.id) || !name.equals(other.name) || !secretHash.equals(other.secretHash) ||
				redirectUris.size() != other.redirectUris.size())
			return false;
		for (URL u: other.redirectUris)
			if (!redirectUris.contains(u))
				return false;
		return true;
	}

	@Override
	public String toString() {
		return String.format("id=%s, name=%s, secretHash=%s, redirectUris=%s", id, name, secretHash, redirectUris);
	}

	@Override
	public String getName() {
		return id;
	}

	public boolean containsRedirectUri(URL redirectUri) {
		return redirectUris.contains(redirectUri);
	}

	public void addRedirectUris(URL redirectUri) {
		this.redirectUris.add(redirectUri);
	}

	public static URL validateClientAndRedirectUri(final AuthStorage authStorage, final String clientId,
	                                               final String redirectUri) {
		try {
			if (redirectUri == null || redirectUri.isEmpty())
				throw new AuthJerseyViolationException(AuthService.REDIRECT_URI, null,
						AuthJerseyViolationExceptionMapper.INVALID_REQUEST, "is not provided");

			if (clientId == null || clientId.isEmpty())
				throw new AuthJerseyViolationException(AuthService.CLIENT_ID, null,
						AuthJerseyViolationExceptionMapper.INVALID_REQUEST, "is not provided");

			Client client;
			try {
				client = authStorage.loadClient(clientId);
			} catch (SessionException e) {
				throw new InternalServerErrorException("Failed to validate client ID: " + clientId);
			}

			// TODO: Validate redirect URI scheme for non-confidential client case

			if (client == null)
				throw new AuthJerseyViolationException(AuthService.CLIENT_ID, null,
						AuthJerseyViolationExceptionMapper.UNAUTHORIZED_CLIENT, "client is not registered");

			java.net.URL uri;
			try {
				uri = new java.net.URL(redirectUri);
			} catch (MalformedURLException e) {
				throw new AuthJerseyViolationException(AuthService.REDIRECT_URI, null,
						AuthJerseyViolationExceptionMapper.INVALID_REQUEST, "malformed redirect uri");
			}

			if (!client.containsRedirectUri(uri))
				throw new AuthJerseyViolationException(AuthService.REDIRECT_URI, null,
						AuthJerseyViolationExceptionMapper.INVALID_REQUEST, "no such redirect uri registered for the given client");

			return uri;
		} catch (Exception ex) {
			LOGGER.error(Utilities.getRootMessage(ex));
			throw ex;
		}
	}

}
