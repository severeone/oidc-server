package severeone.oidc.auth.util.resources;

import severeone.oidc.auth.core.Client;
import severeone.oidc.auth.core.storage.AuthStorage;
import severeone.oidc.auth.db.sessions.SessionException;
import severeone.oidc.auth.util.Utilities;

import io.dropwizard.auth.AuthenticationException;
import io.dropwizard.auth.Authenticator;
import io.dropwizard.auth.basic.BasicCredentials;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;

public class BasicAuthenticator implements Authenticator<BasicCredentials, Client> {

    private static final Logger LOGGER = LoggerFactory.getLogger(BasicAuthenticator.class);
    private final AuthStorage authStorage;

    public BasicAuthenticator(AuthStorage authStorage) {
        this.authStorage = authStorage;
    }

    @Override
    public Optional<Client> authenticate(BasicCredentials credentials) throws AuthenticationException {
        final String clientId = credentials.getUsername();

        Client client;
        try {
            client = authStorage.loadClient(clientId);
        } catch (SessionException e) {
            String msg = "Failed to authenticate client: " + clientId;
            LOGGER.error(msg);
            throw new AuthenticationException(msg, e);
        }
        if (client == null)
            return Optional.empty();

        if (!Utilities.verifyHash(credentials.getPassword(), client.secretHash))
            return Optional.empty();

        return Optional.of(client);
    }

    //TODO: Implement caching
    public static Authenticator<BasicCredentials, Client> cachingAuthenticator() {
        throw new UnsupportedOperationException();
    }
}