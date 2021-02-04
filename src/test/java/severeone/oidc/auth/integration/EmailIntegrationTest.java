package severeone.oidc.auth.integration;

import severeone.oidc.auth.AuthConfig;
import severeone.oidc.auth.api.test.EmailTestResponse;

import com.codahale.metrics.MetricRegistry;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.dropwizard.client.HttpClientBuilder;
import io.dropwizard.configuration.ConfigurationException;
import io.dropwizard.configuration.ConfigurationFactory;
import io.dropwizard.configuration.ConfigurationFactoryFactory;
import io.dropwizard.configuration.ConfigurationSourceProvider;
import io.dropwizard.setup.Bootstrap;

import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.message.BasicNameValuePair;

import org.testng.AssertJUnit;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import javax.validation.Validator;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

@Test(groups = "system")
public class EmailIntegrationTest {

    private AuthConfig configuration;
    private CloseableHttpClient httpClient;

    private String testEmail = "eugene@severeone.com";

    public EmailIntegrationTest() {
    }

    @BeforeClass
    public void before() throws Exception {
        Bootstrap<AuthConfig> bootstrap = new Bootstrap<>(null);
        configuration = parseConfiguration(bootstrap.getConfigurationFactoryFactory(),
                bootstrap.getConfigurationSourceProvider(),
                bootstrap.getValidatorFactory().getValidator(),
                "config.yml",
                AuthConfig.class,
                bootstrap.getObjectMapper());

        httpClient = new HttpClientBuilder(new MetricRegistry()).using(configuration.getHttpClientConfiguration())
                .build("SecurityServer");
    }

    @AfterClass
    public void after() throws Exception {
        if (httpClient != null)
            httpClient.close();
    }

    private HttpPost getPostRequest(String uri) {
        String url = configuration.getIntegrationTestTargetUrl() + "/test/email/" + uri;
        return new HttpPost(url);
    }


    private AuthConfig parseConfiguration(ConfigurationFactoryFactory<AuthConfig> configurationFactoryFactory,
                                 ConfigurationSourceProvider provider,
                                 Validator validator,
                                 String path,
                                 Class<AuthConfig> klass,
                                 ObjectMapper objectMapper) throws IOException, ConfigurationException {
        final ConfigurationFactory<AuthConfig> configurationFactory = configurationFactoryFactory
                .create(klass, validator, objectMapper, "dw");
        if (path != null) {
            return configurationFactory.build(provider, path);
        }
        return configurationFactory.build();
    }

    private void executeRequest(HttpPost postRequest, String resource, Function<CloseableHttpResponse,Object> func) throws Exception {
        CloseableHttpResponse response = httpClient.execute(postRequest);
        try {
            int statusCode = response.getStatusLine().getStatusCode();
            AssertJUnit.assertTrue("AuthServer '/" + resource + "' request returned status " + statusCode, statusCode == 200);
            func.apply(response);
        } finally {
            response.close();
        }

    }

    @Test(groups = "system")
    public void checkEmailTest() throws Exception {
        HttpPost postRequest = getPostRequest("checkexists");
        List<BasicNameValuePair> data = new ArrayList<>();
        data.add(new BasicNameValuePair("email", testEmail));
        UrlEncodedFormEntity entity = new UrlEncodedFormEntity(data, "UTF-8");
        postRequest.setEntity(entity);
        List<String> errors = new ArrayList<>();
        executeRequest(postRequest, "checkexists", response -> {
            ObjectMapper objectMapper = new ObjectMapper();
            try {
                EmailTestResponse result = objectMapper.readValue(response.getEntity().getContent(), EmailTestResponse.class);
                if (result.getResult() != 1 || result.getResult() != 0)
                    errors.add("Unexpected result from 'checkexists' call: " + result.getResult());
            } catch (Throwable e) {
                errors.add(e.getMessage());
            }
            return response;
        });

        AssertJUnit.assertTrue(errors.toString(), errors.isEmpty());
    }

    @Test(groups = "system", dependsOnMethods = { "checkEmailTest" })
    public void sendEmailTest() throws Exception {
        HttpPost postRequest = getPostRequest("sendemail");
        List<BasicNameValuePair> data = new ArrayList<>();
        data.add(new BasicNameValuePair("to", testEmail));
        data.add(new BasicNameValuePair("subject", "integration test"));
        data.add(new BasicNameValuePair("display_name", "integration"));
        data.add(new BasicNameValuePair("body", "This is a test email"));
        UrlEncodedFormEntity entity = new UrlEncodedFormEntity(data, "UTF-8");
        postRequest.setEntity(entity);
        List<String> errors = new ArrayList<>();
        executeRequest(postRequest, "sendemail", response -> {
            ObjectMapper objectMapper = new ObjectMapper();
            try {
                EmailTestResponse result = objectMapper.readValue(response.getEntity().getContent(), EmailTestResponse.class);
                if (result.getResult() != 1)
                    errors.add("Unexpected result from 'sendemail' call: " + result.getResult());
            } catch (Throwable e) {
                errors.add(e.getMessage());
            }
            return response;
        });
        AssertJUnit.assertTrue(errors.toString(), errors.isEmpty());
    }

}
