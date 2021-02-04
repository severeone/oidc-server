package severeone.oidc.auth.core;

import com.fasterxml.jackson.annotation.JsonProperty;

public class UpdateUserJson {

    @JsonProperty("id_token")
    private String signedIDToken;

    @JsonProperty("user")
    private UserJson user;

    public String getSignedIDToken() {
        return signedIDToken;
    }

    public void setSignedIDToken(String signedIDToken) {
        this.signedIDToken = signedIDToken;
    }

    public UserJson getUser() {
        return user;
    }

    public void setUser(UserJson user) {
        this.user = user;
    }

    public static UserJson newUserJson(final String email, final String password, final String firstName,
                                       final String lastName, final String newPassword) {
        UserJson uj = new UserJson();
        uj.email = email;
        uj.password = password;
        uj.firstName = firstName;
        uj.lastName = lastName;
        uj.newPassword = newPassword;
        return uj;
    }

    @Override
    public String toString() {
        return String.format("signedIDToken=%s, user=%s", signedIDToken, user);
    }

    public static class UserJson {

        @JsonProperty
        private String email;

        @JsonProperty
        private String password;

        @JsonProperty("first_name")
        private String firstName;

        @JsonProperty("last_name")
        private String lastName;

        @JsonProperty("new_password")
        private String newPassword;

        public String getEmail() {
            return email;
        }

        public void setEmail(String email) {
            this.email = email;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }

        public String getFirstName() {
            return firstName;
        }

        public void setFirstName(String firstName) {
            this.firstName = firstName;
        }

        public String getLastName() {
            return lastName;
        }

        public void setLastName(String lastName) {
            this.lastName = lastName;
        }

        public String getNewPassword() {
            return newPassword;
        }

        public void setNewPassword(String newPassword) {
            this.newPassword = newPassword;
        }

        @Override
        public String toString() {
            return String.format("email=%s, password=%s, firstName=%s, lastName=%s, newPassword=%s", email, password, firstName, lastName, newPassword);
        }
    }
}
