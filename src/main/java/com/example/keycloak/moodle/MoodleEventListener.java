package com.example.keycloak.moodle;

import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.OperationType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.jboss.logging.Logger;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class MoodleEventListener implements EventListenerProvider {

    private static final Logger LOG = Logger.getLogger(MoodleEventListener.class);
    private final KeycloakSession session;
    private final String moodleApiUrl;
    private final String moodleApiToken;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public MoodleEventListener(KeycloakSession session, String moodleApiUrl, String moodleApiToken) {
        this.session = session;
        this.moodleApiUrl = moodleApiUrl;
        this.moodleApiToken = moodleApiToken;
    }

    @Override
    public void onEvent(Event event) {
        // We are interested in admin events, not user events like login/logout
    }

    @Override
    public void onEvent(AdminEvent adminEvent, boolean includeRepresentation) {
        LOG.info("Inside onEvent method");
        LOG.infof("AdminEvent received. ResourceType: %s, OperationType: %s, AuthDetails: %s",
        adminEvent.getResourceType(),
        adminEvent.getOperationType(),
        adminEvent.getAuthDetails().getUserId());
        if (adminEvent.getResourceType() == org.keycloak.events.admin.ResourceType.USER
        && adminEvent.getOperationType() == OperationType.CREATE) {
            // LOG.info("Keycloak Admin Event: User created. Resource Path: %s", adminEvent.getResourcePath());

            try {
                // Extract user ID from resource path
                String[] pathParts = adminEvent.getResourcePath().split("/");
                String userId = pathParts[pathParts.length - 1];

                // Retrieve user details from Keycloak
                UserModel user = session.users().getUserById(session.realms().getRealm(adminEvent.getRealmId()), userId);

                if (user != null) {
                    LOG.infof("Attempting to sync user %s (%s) to Moodle.", user.getUsername(), user.getEmail());
                    callMoodleApiToCreateUser(user);
                } else {
                    LOG.warnf("Could not find user with ID %s from admin event.", userId);
                }

            } catch (Exception e) {
                LOG.error("Error processing user creation event for Moodle sync: " + e.getMessage(), e);
            }
        }
    }

    private void callMoodleApiToCreateUser(UserModel user) throws IOException {
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpPost httpPost = new HttpPost(moodleApiUrl);

            List<NameValuePair> params = new ArrayList<>();
            params.add(new BasicNameValuePair("wstoken", moodleApiToken));
            params.add(new BasicNameValuePair("wsfunction", "core_user_create_users"));
            params.add(new BasicNameValuePair("moodlewsrestformat", "json"));

            // Moodle expects user data in a specific array format
            params.add(new BasicNameValuePair("users[0][username]", user.getUsername()));
            params.add(new BasicNameValuePair("users[0][password]", generateRandomPassword())); // Moodle requires a password for new users
            params.add(new BasicNameValuePair("users[0][firstname]", user.getFirstName() != null ? user.getFirstName() : ""));
            params.add(new BasicNameValuePair("users[0][lastname]", user.getLastName() != null ? user.getLastName() : ""));
            params.add(new BasicNameValuePair("users[0][email]", user.getEmail()));

            httpPost.setEntity(new UrlEncodedFormEntity(params, StandardCharsets.UTF_8));

            httpClient.execute(httpPost, response -> {
                int statusCode = response.getStatusLine().getStatusCode();
                String responseBody = EntityUtils.toString(response.getEntity());

                if (statusCode >= 200 && statusCode < 300) {
                    LOG.infof("Successfully called Moodle API for user %s. Response: %s", user.getUsername(), responseBody);
                } else {
                    LOG.errorf("Failed to call Moodle API for user %s. Status: %d, Response: %s", user.getUsername(), statusCode, responseBody);
                    // Parse Moodle's error response for more details if needed
                    try {
                        JsonNode jsonResponse = objectMapper.readTree(responseBody);
                        if (jsonResponse.has("exception")) {
                            LOG.errorf("Moodle API Exception: %s (Code: %s, Message: %s)",
                                    jsonResponse.get("exception").asText(),
                                    jsonResponse.get("errorcode").asText(),
                                    jsonResponse.get("message").asText());
                        }
                    } catch (IOException jsonEx) {
                        LOG.error("Could not parse Moodle error response as JSON.", jsonEx);
                    }
                }
                return null;
            });
        }
    }

    private String generateRandomPassword() {
        // Moodle requires a password for user creation.
        // You might want to generate a strong random password,
        // or set a default and instruct the user to change it in Moodle.
        // For simplicity, a basic one is generated here.
        return "TempP@ssw0rd!" + System.currentTimeMillis();
    }

    @Override
    public void close() {
        // Clean up resources if necessary
    }
}