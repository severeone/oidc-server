package severeone.oidc.auth.util.resources.process;

import severeone.oidc.auth.AuthConfig;
import severeone.oidc.auth.core.storage.AuthStorage;

import javax.ws.rs.core.Response;

abstract class RequestProcessor {

    protected final AuthStorage authStorage;
    protected final AuthConfig config;

    public RequestProcessor(final AuthConfig config, final AuthStorage authStorage) {
        this.authStorage = authStorage;
        this.config = config;
    }

    abstract public Response process();
}
