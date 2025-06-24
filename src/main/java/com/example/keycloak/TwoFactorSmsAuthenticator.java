// File: /mnt/data/keycloak-2factor-sms-mfa/src/main/java/com/example/keycloak/TwoFactorSmsAuthenticator.java
package com.example.keycloak;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.UserModel;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Random;

public class TwoFactorSmsAuthenticator implements Authenticator {
    private static final String API_KEY = "<YOUR-API-KEY>";
    private static final String OTP_SESSION_ATTR = "2factor_session";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        String phoneNumber = user.getFirstAttribute("phoneNumber");

        if (phoneNumber == null || phoneNumber.isEmpty()) {
            Response challenge = context.form()
                .setError("Missing phone number.")
                .createErrorPage(Response.Status.BAD_REQUEST);
            context.challenge(challenge);
            return;
        }

        try {
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://2factor.in/API/V1/" + API_KEY + "/SMS/" + phoneNumber + "/AUTOGEN"))
                .GET()
                .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            String body = response.body();

            // Extract session ID from response
            String sessionId = body.split("Details\":\"")[1].split("\"")[0];
            context.getAuthenticationSession().setAuthNote(OTP_SESSION_ATTR, sessionId);

            Response challenge = context.form()
                .createForm("otp.ftl");
            context.challenge(challenge);
        } catch (Exception e) {
            Response challenge = context.form()
                .setError("Failed to send OTP.")
                .createErrorPage(Response.Status.INTERNAL_SERVER_ERROR);
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, challenge);
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String enteredOtp = formData.getFirst("otp");
        String sessionId = context.getAuthenticationSession().getAuthNote(OTP_SESSION_ATTR);

        try {
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://2factor.in/API/V1/" + API_KEY + "/SMS/VERIFY/" + sessionId + "/" + enteredOtp))
                .GET()
                .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            String body = response.body();

            if (body.contains("Success")) {
                context.success();
            } else {
                Response challenge = context.form()
                    .setError("Invalid OTP.")
                    .createForm("otp.ftl");
                context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
            }
        } catch (Exception e) {
            Response challenge = context.form()
                .setError("OTP verification failed.")
                .createErrorPage(Response.Status.INTERNAL_SERVER_ERROR);
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, challenge);
        }
    }

    @Override public void close() {}
    @Override public boolean requiresUser() { return true; }
    @Override public boolean configuredFor(org.keycloak.models.KeycloakSession session, org.keycloak.models.RealmModel realm, UserModel user) { return true; }
    @Override public void setRequiredActions(org.keycloak.models.KeycloakSession session, org.keycloak.models.RealmModel realm, UserModel user) {}
    // @Override public boolean isUserSetupAllowed() { return false; }
}
