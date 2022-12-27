package it.pleaseopen.authenticator.cookieconditionalauthenticator;

import org.keycloak.Config;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

public class CookieConditionalAuthenticatorFactory implements ConditionalAuthenticatorFactory {
    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };


    public static final String ID = "cookie-conditional-authenticator";

    public CookieConditionalAuthenticatorFactory() {
    }

    @Override
    public String getDisplayType() {
        return "condition - cookie";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Test if cookie is present";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return null;
    }


    @Override
    public CookieConditionalAuthenticator getSingleton() {
        return CookieConditionalAuthenticator.SINGLETON;
    }

    @Override
    public void init(Config.Scope scope) {

    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return ID;
    }

}
