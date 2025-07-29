package com.example.keycloak;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.UserModel;
import org.keycloak.authentication.AuthenticationFlowError;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.xml.bind.annotation.XmlValue;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import org.jboss.logging.Logger;
public class TwoFactorSmsAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(TwoFactorSmsAuthenticator.class);

    public static final String apiKey = "a7091539-50e7-11f0-a562-0200cd936042";
    public static final String baseUrl = "https://2factor.in/API/V1/";
    public static final long otpValidityTime = 10*60*1000; // 10 minutes
    public static final long retryCooldownPeriod = 60*60*1000; // 1 hour
    public static final int maxRetries = 3; // MAX 3 retries allowed

    public static final String OTP_SESSION_ATTR = "2factor_session";
    public static final String OTP_VERIFIED_ATTR = "OTP_VERIFIED";
    public static final String OTP_TIMESTAMP_ATTR = "OTP_TIMESTAMP";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        String phoneNumber = user.getFirstAttribute("phoneNumber");
        String isAdminCreated = user.getFirstAttribute("isAdminCreated");
        String blockedUntilStr = user.getFirstAttribute("blockedUntil");
        String otpRetryCountStr = user.getFirstAttribute("otpRetryCount");
        String timestampStr = user.getFirstAttribute("lastOtpSentAt");

        if (isAdminCreated == null) {
            // Attribute doesn't exist yet, create and set to Yes
            user.setSingleAttribute("isAdminCreated", "Yes");
            isAdminCreated = user.getFirstAttribute("isAdminCreated");
            logger.info("Attribute isAdminCreated was missing. Set to " + isAdminCreated);
        } else {
            logger.info("isAdminCreated: " + isAdminCreated);
        }

        Boolean isUpdatePwdRequired = context.getAuthenticationSession().getRequiredActions().contains(UserModel.RequiredAction.UPDATE_PASSWORD.name());

        boolean shouldChallengeOtp = "Yes".equals(isAdminCreated) || isUpdatePwdRequired;

        if (shouldChallengeOtp) {
            logger.info("UPDATE PASSWORD REQUIRED IN USER ACTIONS.");

            long now = System.currentTimeMillis();
            long blockedUntil = blockedUntilStr != null ? Long.parseLong(blockedUntilStr) : 0;
            long otpSentAt = timestampStr != null ? Long.parseLong(timestampStr) : 0;
            int retries = otpRetryCountStr != null ? Integer.parseInt(otpRetryCountStr) : 0;

            //Block OTP until cooldown period is reached
            if (now < blockedUntil && retries >= maxRetries) {
                long waitMinutes = (blockedUntil - now) / 60000;
                Response challenge = context.form()
                    .setError("Too many attempts. Try again in " + waitMinutes + " minutes.")
                    .createErrorPage(Response.Status.TOO_MANY_REQUESTS);
                context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, challenge);
                return;
            }
            
            logger.info("bockedUntilStr " + blockedUntilStr);
            if(blockedUntilStr != null){
                logger.info("blocked until is not null");
            }else{
                logger.info("blocked until is null, that means user hasnt exhausted all attempts, thus setting its value to maximum");
                blockedUntil = Long.MAX_VALUE;
            }
            logger.info("now: " + now + " blockedUntil: " + blockedUntil);
            //set retry count and blocked time = 0 after cooldown period is completed or admin has reset the retry count to 0
            if((now >= blockedUntil) || (retries == 0)){
                user.removeAttribute("blockedUntil");
                user.setSingleAttribute("otpRetryCount", "0");
            }

            logger.info("Sending OTP... from authentication method");
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
        String timestampStr = context.getUser().getFirstAttribute("lastOtpSentAt");

        long now = System.currentTimeMillis();
        long otpSentAt = timestampStr != null ? Long.parseLong(timestampStr) : 0;
        String otpRetryCountStr = context.getUser().getFirstAttribute("otpRetryCount");
        int retries = otpRetryCountStr != null ? Integer.parseInt(otpRetryCountStr) : 0;

        if ((now - otpSentAt) > otpValidityTime) {
            ++retries;
            context.getUser().setSingleAttribute("otpRetryCount", String.valueOf(retries));
            Response challenge = context.form()
                .setError("OTP expired. Please resend OTP.")
                .createForm("otp.ftl");
            context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE, challenge);
            return;
        }

        if (retries >= maxRetries) {
            context.getUser().setSingleAttribute("blockedUntil", String.valueOf(now + retryCooldownPeriod));
            Response challenge = context.form()
                .setError("Maximum OTP attempts reached. Please try again after sometime.")
                .createErrorPage(Response.Status.TOO_MANY_REQUESTS);
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, challenge);
            return;
        }

        try {
            HttpClient client = HttpClient.newHttpClient();
            String url = baseUrl + apiKey + "/SMS/VERIFY/" + sessionId + "/" + enteredOtp;
            logger.info("Full URL with OTP is " + url);
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .GET()
                .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            String body = response.body();

            if (body.contains("Success")) {
                context.getAuthenticationSession().setAuthNote(OTP_VERIFIED_ATTR, "true");
                context.success();
                context.getUser().setSingleAttribute("isAdminCreated", "No");
                //set retry count and blocked time = 0 in case of successful otp validation
                context.getUser().setSingleAttribute("otpRetryCount", "0");
                context.getUser().removeAttribute("blockedUntil");
                logger.info("isAdminCreated set to No");
            } else {
                ++retries;
                context.getUser().setSingleAttribute("otpRetryCount", String.valueOf(retries));

                Response challenge = context.form()
                    .setError("Invalid OTP. Attempt " + retries + " of " + maxRetries)
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

        if (phoneNumber == null || phoneNumber.isEmpty()) {
            Response challenge = context.form()
                .setError("Missing phone number.")
                .createErrorPage(Response.Status.BAD_REQUEST);
            context.challenge(challenge);
            return;
        }

        try {
            HttpClient client = HttpClient.newHttpClient();
            String url = baseUrl + apiKey + "/SMS/" + phoneNumber + "/AUTOGEN";
            logger.info("Sending OTP via URL: " + url);  // ADD THIS LINE
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .GET()
                .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            String body = response.body();

            logger.info("Response Body is: " + body);

            String sessionId = body.split("Details\":\"")[1].split("\"")[0];

            context.getAuthenticationSession().setAuthNote(OTP_SESSION_ATTR, sessionId);
            context.getAuthenticationSession().setAuthNote(OTP_VERIFIED_ATTR, "false");
            context.getUser().setSingleAttribute("lastOtpSentAt", String.valueOf(System.currentTimeMillis()));

            Response challenge = context.form()
                .createForm("otp.ftl");
            context.challenge(challenge);
        } catch (Exception e) {
            logger.error("Failed to send OTP: " + e.getMessage(), e);
            Response challenge = context.form()
                .setError("Failed to send OTP.")
                .createErrorPage(Response.Status.INTERNAL_SERVER_ERROR);
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, challenge);
        }
    }

    private void resendOtp(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        String phoneNumber = user.getFirstAttribute("phoneNumber");
        int retries = context.getUser().getFirstAttribute("otpRetryCount") != null ? Integer.parseInt(context.getUser().getFirstAttribute("otpRetryCount")) : 0;
        if(retries > maxRetries){
            Response challenge = context.form()
            .setError("Maximum OTP attempts reached. Please try again after sometime.")
            .createErrorPage(Response.Status.TOO_MANY_REQUESTS);
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, challenge);
            return;
        }
        logger.info("Resending OTP...");
        sendOtp(context, phoneNumber);
    }

    @Override public void close() {}
    @Override public boolean requiresUser() { return true; }
    @Override public boolean configuredFor(org.keycloak.models.KeycloakSession session, org.keycloak.models.RealmModel realm, UserModel user) { return true; }
    @Override public void setRequiredActions(org.keycloak.models.KeycloakSession session, org.keycloak.models.RealmModel realm, UserModel user) {}
}
