package com.schmalz.servlet.filter;
/*
 * Adapted from https://github.com/keycloak/keycloak/blob/master/adapters/oidc/servlet-filter/src/main/java/org/keycloak/adapters/servlet/KeycloakOIDCFilter.java
 * I changed the logger and added further debugging messages relevant to me
 * I also edited the standard location of the keycloak file
 * Furthermore i added functionality to put a confluence user into the httpsession if a keycloak user was already present
 * I needed to copy some methods over in a one-to-one session since they were private in the superclass
 * Below you will find the original copyright statement
 * Many thanks to the awesome Red Hat developers writing Keycloak, the servlet adapter and putting it all under Apache 2.0!
 */

/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


import com.atlassian.confluence.user.ConfluenceAuthenticator;
import com.atlassian.confluence.user.ConfluenceUser;
import com.atlassian.confluence.user.UserAccessor;
import com.atlassian.spring.container.ContainerManager;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.*;
import org.keycloak.adapters.servlet.FilterRequestAuthenticator;
import org.keycloak.adapters.servlet.KeycloakOIDCFilter;
import org.keycloak.adapters.servlet.OIDCFilterSessionStore;
import org.keycloak.adapters.servlet.OIDCServletHttpFacade;
import org.keycloak.adapters.spi.AuthChallenge;
import org.keycloak.adapters.spi.AuthOutcome;
import org.keycloak.adapters.spi.UserSessionManagement;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.ws.rs.core.UriBuilder;
import java.io.IOException;
import java.io.InputStream;
import java.security.Principal;
import java.util.Enumeration;
import java.util.List;
import java.util.regex.Pattern;


public class AdaptedKeycloakOidcFilter extends KeycloakOIDCFilter {

    private final Logger log = LoggerFactory.getLogger(this.getClass());

    private final KeycloakConfigResolver definedconfigResolver;

    private String realm;
    private String authServer;

    /**
     * Constructor that can be used to define a {@code KeycloakConfigResolver} that will be used at initialization to
     * provide the {@code KeycloakDeployment}.
     *
     * @param definedconfigResolver the resolver
     */
    public AdaptedKeycloakOidcFilter(KeycloakConfigResolver definedconfigResolver) {

        this.definedconfigResolver = definedconfigResolver;
    }

    public AdaptedKeycloakOidcFilter() {

        this(null);
    }

    @Override
    public void init(final FilterConfig filterConfig) throws ServletException {
        String skipPatternDefinition = filterConfig.getInitParameter(SKIP_PATTERN_PARAM);
        if (skipPatternDefinition != null) {
            skipPattern = Pattern.compile(skipPatternDefinition, Pattern.DOTALL);
        }

        String path = "/keycloak.json";
        String pathParam = filterConfig.getInitParameter(CONFIG_PATH_PARAM);
        if (pathParam != null) path = pathParam;
        log.debug("searching for config at path " + path);
        InputStream is = filterConfig.getServletContext().getResourceAsStream(path);


        KeycloakDeployment kd = this.createKeycloakDeploymentFrom(is);
        authServer = kd.getAuthServerBaseUrl();
        realm = kd.getRealm();
        deploymentContext = new AdapterDeploymentContext(kd);
        log.info("Keycloak is using a per-deployment configuration.");


        filterConfig.getServletContext().setAttribute(AdapterDeploymentContext.class.getName(), deploymentContext);
        nodesRegistrationManagement = new NodesRegistrationManagement();
    }

    private KeycloakDeployment createKeycloakDeploymentFrom(InputStream is) {

        if (is == null) {
            log.error("No adapter configuration. Keycloak is unconfigured and will deny all requests.");
            return new KeycloakDeployment();
        }
        return KeycloakDeploymentBuilder.build(is);
    }


    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;
        HttpSession session = request.getSession();
        String query = request.getQueryString();

        if (shouldSkip(request)) {
            chain.doFilter(req, res);
            return;
        }


        RefreshableKeycloakSecurityContext account = (RefreshableKeycloakSecurityContext) session.getAttribute(
                KeycloakSecurityContext.class.getName());
/*
        logSessionAttributes(session);
        String queryLog = query != null ? query : "NULL";
        log.warn("Quey: " + queryLog);
*/
        if (query != null && query.contains("logout=true")) {
            prepareLogout(session);
        }
        if (account != null && session.getAttribute(ConfluenceAuthenticator.LOGGED_OUT_KEY) != null) {
            if (handleLogout(account, session)) {
                log.warn("logout successful");
                response.sendRedirect(authServer + "/realms/" + realm + "/protocol/openid-connect/auth?" +
                        "response_type=code&client_id=confluence&redirect_uri=http%3A%2F%2Flocalhost%3A1990%2Fconfluence%2F");
            } else
                log.warn("failed logout");
            chain.doFilter(req, res);
            return;
        }

        Principal principal = (Principal) session.getAttribute(ConfluenceAuthenticator.LOGGED_IN_KEY);

        if (principal != null && session.getAttribute(ConfluenceAuthenticator.LOGGED_OUT_KEY) == null) {
            log.info("confluence user " + principal.getName() + " is already authenticated, continuing");
            chain.doFilter(req, res);
            return;
        }
        //no need to check for logged in key, we only arrive here if there is no principal object from confluence

        if (account != null) {
            /* try to log the user into confluence */

            if (handleLogin(account.getToken().getPreferredUsername(), session))
                log.debug("login successful");
            else
                log.info("login failed");

            chain.doFilter(req, res);
            return;

        }

        /* unchanged code, only changes are additional logging */

        OIDCServletHttpFacade facade = new OIDCServletHttpFacade(request, response);
        KeycloakDeployment deployment = deploymentContext.resolveDeployment(facade);
        if (deployment == null || !deployment.isConfigured()) {
            response.sendError(403);
            log.error("deployment not configured");
            return;
        }

        PreAuthActionsHandler preActions = new PreAuthActionsHandler(new UserSessionManagement() {
            @Override
            public void logoutAll() {
                log.debug("landed in logoutAll method");
                if (idMapper != null) {
                    idMapper.clear();
                }
            }

            @Override
            public void logoutHttpSessions(List<String> ids) {

                log.debug("logoutHttpSessions");
                for (String id : ids) {
                    log.debug("removed idMapper: " + id);
                    idMapper.removeSession(id);
                }

            }
        }, deploymentContext, facade);

        if (preActions.handleRequest()) {
            return;
        }


        nodesRegistrationManagement.tryRegister(deployment);
        OIDCFilterSessionStore tokenStore = new OIDCFilterSessionStore(request, facade, 100000, deployment, idMapper);
        tokenStore.checkCurrentToken();


        FilterRequestAuthenticator authenticator = new FilterRequestAuthenticator(deployment, tokenStore, facade, request, 8443);
        AuthOutcome outcome = authenticator.authenticate();
        if (outcome == AuthOutcome.AUTHENTICATED) {
            log.info("AUTHENTICATED");
            if (facade.isEnded()) {
                return;
            }
            AuthenticatedActionsHandler actions = new AuthenticatedActionsHandler(deployment, facade);
            if (actions.handledRequest()) {
                return;
            } else {
                HttpServletRequestWrapper wrapper = tokenStore.buildWrapper();
                chain.doFilter(wrapper, res);
                return;
            }
        }
        AuthChallenge challenge = authenticator.getChallenge();
        if (challenge != null) {
            log.info("challenge");
            challenge.challenge(facade);
            return;
        }
        response.sendError(403);
        /*end of unchanged code, only changes are additional logging */
    }

    private boolean handleLogout(KeycloakSecurityContext account, HttpSession session) {
        logSessionAttributes(session);
        session.removeAttribute(ConfluenceAuthenticator.LOGGED_OUT_KEY);
        if (account != null) {
            log.warn("attempting to logout user " + account.getIdToken().getPreferredUsername());
            HttpGet httpGet = new HttpGet();
            httpGet.setURI(UriBuilder.fromUri(authServer + "/realms/" + realm + "/protocol" +
                    "/openid-connect/logout?id_token_hint=" + account.getIdTokenString()).build());
            log.debug("trying get with " + httpGet.getURI());
            session.removeAttribute(KeycloakSecurityContext.class.getName());
            try {
                HttpClient client = new DefaultHttpClient();
                HttpResponse httpResponse = client.execute(httpGet);
                log.debug(httpResponse.getStatusLine().toString());
                return true;
            } catch (Exception ex) {
                log.warn("Caught exception " + ex);

            }
        }
        return false;

    }

    private void prepareLogout(HttpSession session) {
        log.warn("preparing logout");
        session.setAttribute(ConfluenceAuthenticator.LOGGED_OUT_KEY, Boolean.TRUE);
    }

    private boolean handleLogin(String userName, HttpSession session) {
        log.info("Found a valid KC user, attempting login to confluence");
        ConfluenceUser user = getAccessor().getUserByName(userName);
        if (user == null) {
            log.debug("Authentication unsuccessful, user does not exist in Confluence");
            return false;
        } else {
            Object object = session.getAttribute(ConfluenceAuthenticator.LOGGED_OUT_KEY);
            if (object != null) {
                log.debug("removed logged out key");
                session.removeAttribute(ConfluenceAuthenticator.LOGGED_OUT_KEY);
            }
            session.setAttribute(ConfluenceAuthenticator.LOGGED_IN_KEY, user);
            log.debug("Successfully authenticated user " + user.getName() + " to Confluence");

            return true;
        }
    }

    /**
     * Decides whether this {@link Filter} should skip the given {@link HttpServletRequest} based on the configured {@link KeycloakOIDCFilter#skipPattern}.
     * Patterns are matched against the {@link HttpServletRequest#getRequestURI() requestURI} of a request without the context-path.
     * A request for {@code /myapp/index.html} would be tested with {@code /index.html} against the skip pattern.
     * Skipped requests will not be processed further by {@link KeycloakOIDCFilter} and immediately delegated to the {@link FilterChain}.
     *
     * @param request the request to check
     * @return {@code true} if the request should not be handled,
     * {@code false} otherwise.
     */
    private boolean shouldSkip(HttpServletRequest request) {

        if (request.getQueryString() != null && request.getQueryString().contains("noSSO")) {
            log.warn("ignoring this request due to queryparam 'noSSO'");
            return true;
        }
        String uri = request.getRequestURI();
        if (uri.contains("/rest")) {
            log.info("ignoring the request because its a REST call");
            return true;
        }

        if (uri.contains("/download/")) {
            log.warn("confluence trying to get some ressources, ignoring the request");
            return true;
        }
        if (uri.contains("/dologin.action")) {
            log.warn("confluence is processing the login request, ignoring");
            return true;
        }
        if (skipPattern == null) {
            log.info("Didnt skip the request");
            return false;
        }
        String requestPath = request.getRequestURI().substring(request.getContextPath().length());
        log.info("Possibly skipping the request with path " + requestPath);
        return skipPattern.matcher(requestPath).matches();
    }

    private void logSessionAttributes(HttpSession session) {

        Enumeration<String> enumeration = session.getAttributeNames();
        log.warn("start of enum");
        while (enumeration.hasMoreElements()) {
            log.warn(enumeration.nextElement());
        }
        log.warn("end of enum");
    }

    private UserAccessor getAccessor() {
        return (UserAccessor) ContainerManager.getComponent("userAccessor");
    }

}