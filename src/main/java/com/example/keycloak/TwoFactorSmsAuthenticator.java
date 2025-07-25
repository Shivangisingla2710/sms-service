package com.example.keycloak;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.UserModel;
import org.keycloak.authentication.AuthenticationFlowError;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import org.jboss.logging.Logger;

public class TwoFactorSmsAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(TwoFactorSmsAuthenticator.class);

    private static final String API_KEY = "a7091539-50e7-11f0-a562-0200cd936042";
    private static final String OTP_SESSION_ATTR = "2factor_session";
    private static final String OTP_VERIFIED_ATTR = "OTP_VERIFIED";
    private static final String OTP_TIMESTAMP_ATTR = "OTP_TIMESTAMP";
    // private static final String OTP_RETRIES_ATTR = "OTP_RETRIES";
    // private static final String OTP_BLOCKED_UNTIL_ATTR = "OTP_BLOCKED_UNTIL";

    // private static final int MAX_RETRIES = 5;
    private static final long OTP_VALIDITY_MILLIS = 2 * 60 * 1000; // 2 minutes
    // private static final long RETRY_COOLDOWN_MILLIS = 5 * 60 * 1000; // 5 minutes

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        String phoneNumber = user.getFirstAttribute("phoneNumber");
        String isAdminCreated = user.getFirstAttribute("isAdminCreated");

        if (isAdminCreated == null) {
            // Attribute doesn't exist yet, create and set to Yes
            user.setSingleAttribute("isAdminCreated", "Yes");
            isAdminCreated = user.getFirstAttribute("isAdminCreated");
            logger.info("Attribute isAdminCreated was missing. Set to " + isAdminCreated);
        } else {
            logger.info("isAdminCreated: " + isAdminCreated);
        }

        Boolean isUpdatePwdRequired = context.getAuthenticationSession().getRequiredActions().contains(UserModel.RequiredAction.UPDATE_PASSWORD.name());

        // String otpVerified = context.getAuthenticationSession().getAuthNote(OTP_VERIFIED_ATTR);
        boolean shouldChallengeOtp = "Yes".equals(isAdminCreated) || isUpdatePwdRequired;

        if (shouldChallengeOtp) {
            logger.info("UPDATE PASSWORD REQUIRED IN USER ACTIONS.");
            
            // long now = System.currentTimeMillis();
            // String blockedUntilStr = context.getAuthenticationSession().getAuthNote(OTP_BLOCKED_UNTIL_ATTR);
            // if (blockedUntilStr != null && now < Long.parseLong(blockedUntilStr)) {
            //     long waitMinutes = (Long.parseLong(blockedUntilStr) - now) / 60000;
            //     Response challenge = context.form()
            //         .setError("Too many attempts. Try again in " + waitMinutes + " minutes.")
            //         .createErrorPage(Response.Status.TOO_MANY_REQUESTS);
            //     context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, challenge);
            //     return;
            // }

            sendOtp(context, phoneNumber);
        } else {
            context.success();
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

        if ("true".equals(formData.getFirst("resendOtp"))) {
            resendOtp(context);
            return;
        }

        String enteredOtp = formData.getFirst("otp");
        String sessionId = context.getAuthenticationSession().getAuthNote(OTP_SESSION_ATTR);
        String timestampStr = context.getAuthenticationSession().getAuthNote(OTP_TIMESTAMP_ATTR);
        // String retriesStr = context.getAuthenticationSession().getAuthNote(OTP_RETRIES_ATTR);

        long now = System.currentTimeMillis();
        long otpSentAt = timestampStr != null ? Long.parseLong(timestampStr) : 0;
        // int retries = retriesStr != null ? Integer.parseInt(retriesStr) : 0;

        if (now - otpSentAt > OTP_VALIDITY_MILLIS) {
            Response challenge = context.form()
                .setError("OTP expired. Please resend OTP.")
                .createForm("otp.ftl");
            context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE, challenge);
            return;
        }

        // if (retries >= MAX_RETRIES) {
        //     context.getAuthenticationSession().setAuthNote(OTP_BLOCKED_UNTIL_ATTR, String.valueOf(now + RETRY_COOLDOWN_MILLIS));
        //     Response challenge = context.form()
        //         .setError("Maximum OTP attempts reached. Please try again after sometime.")
        //         .createErrorPage(Response.Status.TOO_MANY_REQUESTS);
        //     context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, challenge);
        //     return;
        // }

        try {
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://2factor.in/API/V1/" + API_KEY + "/SMS/VERIFY/" + sessionId + "/" + enteredOtp))
                .GET()
                .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            String body = response.body();

            if (body.contains("Success")) {
                context.getAuthenticationSession().setAuthNote(OTP_VERIFIED_ATTR, "true");
                context.success();
                context.getUser().setSingleAttribute("isAdminCreated", "No");
                logger.info("isAdminCreated set to No");
            } else {
                // retries++;
                // context.getAuthenticationSession().setAuthNote(OTP_RETRIES_ATTR, String.valueOf(retries));
                context.getAuthenticationSession().setAuthNote("OTP_LAST_ATTEMPT_TIME", String.valueOf(System.currentTimeMillis()));

                Response challenge = context.form()
                    // .setError("Invalid OTP. Attempt " + retries + " of " + MAX_RETRIES)
                    .setError("Invalid OTP. Please Try again")
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

    private void sendOtp(AuthenticationFlowContext context, String phoneNumber) {

        // int attempts = Integer.parseInt(context.getAuthenticationSession().getAuthNote("OTP_ATTEMPTS") != null ? context.getAuthenticationSession().getAuthNote("OTP_ATTEMPTS") : "0");
        // String lastAttemptTimeStr = context.getAuthenticationSession().getAuthNote("OTP_LAST_ATTEMPT_TIME");
        // long now_1 = System.currentTimeMillis();

        // if (attempts >= MAX_RETRIES && lastAttemptTimeStr != null) {
        //     long lastAttemptTime = Long.parseLong(lastAttemptTimeStr);
        //     if ((now_1 - lastAttemptTime) < RETRY_COOLDOWN_MILLIS) {
        //         Response challenge = context.form()
        //             .setError("Maximum attempts reached. Please try again after some time.")
        //             .createErrorPage(Response.Status.TOO_MANY_REQUESTS);
        //         context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
        //         return;
        //     } else {
        //         // Reset attempts after cooldown
        //         context.getAuthenticationSession().setAuthNote("OTP_ATTEMPTS", "0");
        //         context.getAuthenticationSession().removeAuthNote("OTP_LAST_ATTEMPT_TIME");
        //     }
        // }

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

            String sessionId = body.split("Details\":\"")[1].split("\"")[0];
            long now = System.currentTimeMillis();

            context.getAuthenticationSession().setAuthNote(OTP_SESSION_ATTR, sessionId);
            context.getAuthenticationSession().setAuthNote(OTP_TIMESTAMP_ATTR, String.valueOf(now));
            // 👇 Do not reset retries here!
            // if (context.getAuthenticationSession().getAuthNote(OTP_RETRIES_ATTR) == null) {
            //     context.getAuthenticationSession().setAuthNote(OTP_RETRIES_ATTR, "0");
            // }
            context.getAuthenticationSession().setAuthNote(OTP_VERIFIED_ATTR, "false");

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

    private void resendOtp(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        String phoneNumber = user.getFirstAttribute("phoneNumber");
        logger.info("Resending OTP...");
        sendOtp(context, phoneNumber);
    }

    @Override public void close() {}
    @Override public boolean requiresUser() { return true; }
    @Override public boolean configuredFor(org.keycloak.models.KeycloakSession session, org.keycloak.models.RealmModel realm, UserModel user) { return true; }
    @Override public void setRequiredActions(org.keycloak.models.KeycloakSession session, org.keycloak.models.RealmModel realm, UserModel user) {}
}
