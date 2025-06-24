// File: /mnt/data/keycloak-2factor-sms-mfa/src/main/java/com/example/keycloak/TwoFactorSmsAuthenticatorFactory.java
package com.example.keycloak;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.KeycloakSession;

import java.util.Collections;
import java.util.List;
import org.keycloak.provider.ProviderConfigProperty;

import org.keycloak.Config;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.authentication.ConfigurableAuthenticatorFactory;
import org.keycloak.models.KeycloakSessionFactory;

public class TwoFactorSmsAuthenticatorFactory implements AuthenticatorFactory, ConfigurableAuthenticatorFactory {
    public static final String ID = "2factor-sms-authenticator";

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getDisplayType() {
        return "2Factor SMS OTP Authenticator";
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new TwoFactorSmsAuthenticator();
    }

    @Override
    public void init(Config.Scope config) {}

    @Override
    public void postInit(KeycloakSessionFactory factory) {}

    @Override
    public void close() {}

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Sends OTP using 2Factor.in";
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Collections.emptyList();
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[] {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.ALTERNATIVE,
            AuthenticationExecutionModel.Requirement.DISABLED
        };
    }
}
