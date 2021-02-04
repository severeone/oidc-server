package severeone.oidc.auth.api.test;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;

public class EmailTestResponse {
    private Integer result;

    public Integer getResult() {
        return this.result;
    }

    @JsonCreator
    public EmailTestResponse(@JsonProperty("result") Integer result) {
        this.result = result;
    }

    @Override
    public String toString() {
        return String.valueOf(result);
    }

    public static void main(final String[] args) throws Exception {
        String jsonString = "{\"result\": 1}";
        ObjectMapper mapper = new ObjectMapper();
        EmailTestResponse bean = mapper.readValue(jsonString, EmailTestResponse.class);
        System.out.println(bean.toString());
    }
}
