package com.example.keycloak.moodle;

import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class MoodleEventListenerFactory implements EventListenerProviderFactory {

    public static final String PROVIDER_ID = "moodle-user-sync-listener";

    private String moodleApiUrl;
    private String moodleApiToken;

    @Override
    public EventListenerProvider create(KeycloakSession session) {
        return new MoodleEventListener(session, "https://6d5d580d5eaa.ngrok-free.app/moodle/webservice/rest/server.php", "68a78f9b25a0d59d890bb52b2c57e0f1");
    }

    @Override
    public void init(Config.Scope config) {
        // Read configuration from Keycloak's standalone.xml or environment variables
        // For Docker, environment variables are often preferred
        // this.moodleApiUrl = config.get("moodleApiUrl", System.getenv("MOODLE_API_URL"));
        this.moodleApiUrl = "https://6d5d580d5eaa.ngrok-free.app/moodle/webservice/rest/server.php";
        this.moodleApiToken = "68a78f9b25a0d59d890bb52b2c57e0f1";

        if (moodleApiUrl == null || moodleApiToken == null) {
            throw new RuntimeException("Moodle API URL or Token is not configured for the event listener.");
        }
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // Not needed for this example
    }

    @Override
    public void close() {
        // Not needed for this example
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}