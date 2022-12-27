package it.pleaseopen.authenticator.cookieconditionalauthenticator;

import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.util.AcrStore;
import org.keycloak.models.*;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;
import java.util.Map;


public class CookieConditionalAuthenticator implements ConditionalAuthenticator {
    public static final CookieConditionalAuthenticator SINGLETON = new CookieConditionalAuthenticator();

    private String getConfigSettingOrDefault(AuthenticationFlowContext context, String key, String defaultValue) {
        AuthenticatorConfigModel authenticatorConfig = context.getAuthenticatorConfig();
        if (authenticatorConfig == null) {
            return defaultValue;
        }
        Map<String, String> config = authenticatorConfig.getConfig();
        if (config == null) {
            return defaultValue;
        }
        return config.getOrDefault(key, defaultValue);
    }

    @Override
    public boolean matchCondition(AuthenticationFlowContext authenticationFlowContext ) {
        AuthenticationManager.AuthResult authResult = AuthenticationManager.authenticateIdentityCookie(authenticationFlowContext.getSession(),
                authenticationFlowContext.getRealm(), true);
        if (authResult == null) {
            return false;
        } else {
            AuthenticationSessionModel authSession = authenticationFlowContext.getAuthenticationSession();
            LoginProtocol protocol = authenticationFlowContext.getSession().getProvider(LoginProtocol.class, authSession.getProtocol());
            authSession.setAuthNote(Constants.LOA_MAP, authResult.getSession().getNote(Constants.LOA_MAP));
            authenticationFlowContext.setUser(authResult.getUser());
            AcrStore acrStore = new AcrStore(authSession);

            // Cookie re-authentication is skipped if re-authentication is required
            if (protocol.requireReauthentication(authResult.getSession(), authSession)) {
                // Full re-authentication, so we start with no loa
                acrStore.setLevelAuthenticatedToCurrentRequest(Constants.NO_LOA);
                authSession.setAuthNote(AuthenticationManager.FORCED_REAUTHENTICATION, "true");
                authenticationFlowContext.setForwardedInfoMessage(Messages.REAUTHENTICATE);
                return false;
            } else {
                int previouslyAuthenticatedLevel = acrStore.getHighestAuthenticatedLevelFromPreviousAuthentication();
                if (acrStore.getRequestedLevelOfAuthentication() > previouslyAuthenticatedLevel) {
                    // Step-up authentication, we keep the loa from the existing user session.
                    // The cookie alone is not enough and other authentications must follow.
                    acrStore.setLevelAuthenticatedToCurrentRequest(previouslyAuthenticatedLevel);
                    return false;
                } else {
                    // Cookie only authentication
                    acrStore.setLevelAuthenticatedToCurrentRequest(previouslyAuthenticatedLevel);
                    authSession.setAuthNote(AuthenticationManager.SSO_AUTH, "true");
                    authenticationFlowContext.attachUserSession(authResult.getSession());
                    return true;
                }
            }
        }
    }

    @Override
    public void action(AuthenticationFlowContext authenticationFlowContext) {
        AuthenticationManager.AuthResult authResult = AuthenticationManager.authenticateIdentityCookie(authenticationFlowContext.getSession(),
                authenticationFlowContext.getRealm(), true);
        if (authResult == null) {
            authenticationFlowContext.attempted();
        } else {
            AuthenticationSessionModel authSession = authenticationFlowContext.getAuthenticationSession();
            LoginProtocol protocol = authenticationFlowContext.getSession().getProvider(LoginProtocol.class, authSession.getProtocol());
            authSession.setAuthNote(Constants.LOA_MAP, authResult.getSession().getNote(Constants.LOA_MAP));
            authenticationFlowContext.setUser(authResult.getUser());
            AcrStore acrStore = new AcrStore(authSession);

            // Cookie re-authentication is skipped if re-authentication is required
            if (protocol.requireReauthentication(authResult.getSession(), authSession)) {
                // Full re-authentication, so we start with no loa
                acrStore.setLevelAuthenticatedToCurrentRequest(Constants.NO_LOA);
                authSession.setAuthNote(AuthenticationManager.FORCED_REAUTHENTICATION, "true");
                authenticationFlowContext.setForwardedInfoMessage(Messages.REAUTHENTICATE);
                authenticationFlowContext.attempted();
            } else {
                int previouslyAuthenticatedLevel = acrStore.getHighestAuthenticatedLevelFromPreviousAuthentication();
                if (acrStore.getRequestedLevelOfAuthentication() > previouslyAuthenticatedLevel) {
                    // Step-up authentication, we keep the loa from the existing user session.
                    // The cookie alone is not enough and other authentications must follow.
                    acrStore.setLevelAuthenticatedToCurrentRequest(previouslyAuthenticatedLevel);
                    authenticationFlowContext.attempted();
                } else {
                    // Cookie only authentication
                    acrStore.setLevelAuthenticatedToCurrentRequest(previouslyAuthenticatedLevel);
                    authSession.setAuthNote(AuthenticationManager.SSO_AUTH, "true");
                    authenticationFlowContext.attachUserSession(authResult.getSession());
                    authenticationFlowContext.success();
                }
            }
        }
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {

    }

    @Override
    public void close() {

    }

}