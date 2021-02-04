package severeone.oidc.auth.core;

import java.beans.ConstructorProperties;

// Access token related data
public class AccessData {

    public String refreshToken;
    public String encryptedAccessToken;
    public String clientId;
    public int userId;

    @ConstructorProperties({"refresh_token", "encrypted_access_token", "client_id", "user_id"})
    public AccessData(String refreshToken, String encryptedAccessToken, String clientId, int userId) {
        this.refreshToken = refreshToken;
        this.encryptedAccessToken = encryptedAccessToken;
        this.clientId = clientId;
        this.userId = userId;
    }

    public AccessData(AccessData other) {
        this.refreshToken = other.refreshToken;
        this.encryptedAccessToken = other.encryptedAccessToken;
        this.clientId = other.clientId;
        this.userId = other.userId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        AccessData other = (AccessData) o;
        return encryptedAccessToken.equals(other.encryptedAccessToken) &&
                refreshToken.equals(other.refreshToken) &&
                clientId.equals(other.clientId) &&
                userId == other.userId;
    }
}
