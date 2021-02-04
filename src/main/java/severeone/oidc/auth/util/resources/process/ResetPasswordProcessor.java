package severeone.oidc.auth.util.resources.process;

import severeone.oidc.auth.AuthConfig;
import severeone.oidc.auth.core.User;
import severeone.oidc.auth.core.storage.AuthStorage;
import severeone.oidc.auth.db.users.UserException;
import severeone.oidc.auth.util.resources.AuthJerseyViolationException;
import severeone.oidc.auth.util.resources.AuthJerseyViolationExceptionMapper;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.CloseableHttpClient;

import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.UUID;

import static severeone.oidc.auth.resources.AuthService.EMAIL;

public class ResetPasswordProcessor extends RequestProcessor {

    private static final String AUTHCODE = "authcode";

    private String email;
    private CloseableHttpClient httpClient;

    public ResetPasswordProcessor(final AuthConfig config, final AuthStorage authStorage) {
        super(config, authStorage);
    }

    public ResetPasswordProcessor email(final String email) {
        this.email = email;
        return this;
    }

    public ResetPasswordProcessor httpClient(final CloseableHttpClient httpClient) {
        this.httpClient = httpClient;
        return this;
    }

    @Override
    public Response process() {
        final String verificationCode = UUID.randomUUID().toString();

        User u;
        try {
            u = authStorage.loadUser(email);
        } catch (UserException e) {
            throw new InternalServerErrorException("Failed to load user");
        }
        if (u == null)
            throw new AuthJerseyViolationException(EMAIL, null,
                    AuthJerseyViolationExceptionMapper.INVALID_REQUEST, "is not registered");

        try {
            authStorage.saveEmailVerificationCode(email, verificationCode);
        } catch (UserException e) {
            throw new InternalServerErrorException("Failed to save a verification code");
        }

        URI uri;
        try {
            uri = new URIBuilder(config.getResetPasswordAPIEndpoint())
                    .setParameter(EMAIL, email)
                    .setParameter(AUTHCODE, verificationCode)
                    .build();
        } catch (URISyntaxException e) {
            throw new InternalServerErrorException("Failed to get reset password API endpoint");
        }

        HttpPut putRequest = new HttpPut(uri);
        CloseableHttpResponse res;
        try {
            res = httpClient.execute(putRequest);
        } catch (IOException e) {
            throw new InternalServerErrorException("Failed to make a PUT request to API server");
        }

        return Response
                .status(res.getStatusLine().getStatusCode())
                .type(MediaType.APPLICATION_JSON)
                .build();
    }
}
