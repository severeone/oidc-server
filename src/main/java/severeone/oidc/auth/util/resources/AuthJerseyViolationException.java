package severeone.oidc.auth.util.resources;

import io.dropwizard.jersey.validation.JerseyViolationException;

public class AuthJerseyViolationException extends JerseyViolationException {

    public final String errorCode, errorDescription, parameterName, redirectUri, state;

    public AuthJerseyViolationException(final String parameterName, final String redirectUri,
                                        final String errorCode, final String errorDescription) {
        super(null, null);
        this.errorCode = errorCode;
        this.errorDescription = errorDescription;
        this.parameterName = parameterName;
        this.redirectUri = redirectUri;
        this.state = null;
    }

    public AuthJerseyViolationException(final String parameterName, final String redirectUri,
                                        final String errorCode, final String errorDescription,
                                        final String state) {
        super(null, null);
        this.errorCode = errorCode;
        this.errorDescription = errorDescription;
        this.parameterName = parameterName;
        this.redirectUri = redirectUri;
        this.state = state;
    }
}
