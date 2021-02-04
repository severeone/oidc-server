package severeone.oidc.auth.util.resources.process;

import severeone.oidc.auth.AuthConfig;
import severeone.oidc.auth.core.User;
import severeone.oidc.auth.core.storage.AuthStorage;
import severeone.oidc.auth.db.users.UserException;
import severeone.oidc.auth.tokens.AccessToken;

import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.HashMap;
import java.util.Map;

import static severeone.oidc.auth.resources.AuthService.*;

public class UserInfoProcessor extends RequestProcessor {

    private AccessToken accessToken;

    public UserInfoProcessor(final AuthConfig config, final AuthStorage storage) {
        super(config, storage);
    }

    public UserInfoProcessor accessToken(final AccessToken accessToken) {
        this.accessToken = accessToken;
        return this;
    }

    @Override
    public Response process() {
        User u = extractUser();
        Map<String, Object> userJson = new HashMap<String, Object>() {{
            put(EMAIL, u.email);
            put(USER_TYPE, u.type.name());
            put(OPENID_PROVIDER_ORIGIN, CASE_OP);
        }};
        if (u.firstName != null)
            userJson.put(FIRST_NAME, u.firstName);
        if (u.lastName != null)
            userJson.put(LAST_NAME, u.lastName);

        return Response
                .ok()
                .type(MediaType.APPLICATION_JSON_TYPE)
                .entity(userJson)
                .build();
    }

    private User extractUser() {
        User u = null;
        try {
            u = authStorage.loadUser(Integer.parseInt(accessToken.getUserId()));
        } catch (UserException e) {
            throw new InternalServerErrorException("Failed to load user by id");
        }

        if (u == null)
            throw new InternalServerErrorException("Failed to load user by id");

        return u;
    }
}
