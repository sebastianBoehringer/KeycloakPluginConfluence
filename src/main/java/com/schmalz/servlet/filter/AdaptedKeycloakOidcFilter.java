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
import com.atlassian.plugin.spring.scanner.annotation.component.Scanned;
import com.atlassian.plugin.spring.scanner.annotation.imports.ComponentImport;
import com.atlassian.sal.api.pluginsettings.PluginSettings;
import com.atlassian.sal.api.pluginsettings.PluginSettingsFactory;
import com.atlassian.spring.container.ContainerManager;
import com.schmalz.servlet.ConfigServlet;
import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.*;
import org.keycloak.adapters.servlet.KeycloakOIDCFilter;
import org.keycloak.representations.adapters.config.AdapterConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.ws.rs.core.UriBuilder;
import java.io.IOException;
import java.io.InputStream;
import java.security.Principal;
import java.util.Enumeration;
import java.util.Map;

@Scanned
public class AdaptedKeycloakOidcFilter extends KeycloakOIDCFilter {
    public static final String SETTINGS_KEY = AdaptedKeycloakOidcFilter.class.getName() + "-keycloakConfluencePlugin-SettingsKey";
    private final Logger log = LoggerFactory.getLogger(this.getClass());
    public static final String EXCEPTION_DURING_UPDATE = "exception-during-update";
    @ComponentImport
    private final PluginSettingsFactory factory;
    private String realm;
    private String authServer;
    private FilterConfig filterConfiguration;
    private String resource;
    boolean disabled = false;
    boolean initialConfigurationNeeded = false;

    /**
     * Constructor that can be used to define a {@code ConfigResolver} that will be used at initialization to
     * provide the {@code KeycloakDeployment}.
     *
     * @param definedconfigResolver the resolver
     */
    public AdaptedKeycloakOidcFilter(KeycloakConfigResolver definedconfigResolver, PluginSettingsFactory pluginSettingsFactory) {

        factory = pluginSettingsFactory;
    }

    public AdaptedKeycloakOidcFilter(PluginSettingsFactory factory) {

        this(null, factory);
    }

    @Override
    public void init(final FilterConfig filterConfig) throws ServletException {

        super.init(filterConfig);
        String pathParam = filterConfig.getInitParameter(CONFIG_PATH_PARAM);
        String path = pathParam == null ? "/keycloak.json" : pathParam;
        log.info("searching for config at path " + path);

        String debugParam = filterConfig.getInitParameter("plugin.debug");

        //saving filterconfig so i can easily access the json-file later
        filterConfiguration = filterConfig;
        InputStream is = filterConfig.getServletContext().getResourceAsStream(path);
        InputStream is2 = filterConfig.getServletContext().getResourceAsStream(path);
        if (is != null) {
            disabled = false;
            AdapterConfig deployment = KeycloakDeploymentBuilder.loadAdapterConfig(is);
            KeycloakDeployment ment = KeycloakDeploymentBuilder.build(is2);
            /*
            plugin settings can only store: String, List<String>, Map<String,String>; thread below describes other possibilities
            */
            //https://community.atlassian.com/t5/Answers-Developer-Questions/PluginSettings-vs-Active-Objects/qaq-p/485817
            realm = deployment.getRealm();
            authServer = deployment.getAuthServerUrl();
            deploymentContext = new AdapterDeploymentContext(ment);
            PluginSettings settings = factory.createSettingsForKey(SETTINGS_KEY);
            Object test = settings.get(ConfigServlet.REALM);
            this.deploymentContext = new AdapterDeploymentContext(ment);
            /*
             * method takes too long if a call to either (@code handleUpdate) or (@initConfig) is made
             * So we just set flags to indicate that those methods should be called when processing a request
             */
            if (test != null) {
                //method only changes the deploymentcontext so it does not need to know about the persisted settings
                settings.put(ConfigServlet.UPDATED_SETTINGS_KEY, "true");

            } else {
                /*
                fresh instance of CONFLUENCE or first time using the plugin, so the basic settings will be imported from the
                json file
                */
                initialConfigurationNeeded = true;

            }

        } else {
            log.error("could not find configuration file, this plugin will disable itself");
        }
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        if (initialConfigurationNeeded) {
            PluginSettings settings = factory.createSettingsForKey(SETTINGS_KEY);
            try (InputStream is = filterConfiguration.getServletContext().getResourceAsStream("/keycloak.json")) {
                initFromConfig(KeycloakDeploymentBuilder.loadAdapterConfig(is), settings);
                initialConfigurationNeeded = false;
                log.warn("Initial configuration done");
                log.warn("removed stuff from settings");
                HttpServletResponse response = (HttpServletResponse) res;
                response.sendRedirect(((HttpServletRequest) req).getRequestURI());
                return;
            } catch (Exception e) {
                log.warn("Initial configuration failed");
            }
        }
        HttpServletRequest request = (HttpServletRequest) req;
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
        PluginSettings settings = factory.createSettingsForKey(SETTINGS_KEY);
        if (Boolean.parseBoolean((String) settings.get(ConfigServlet.UPDATED_SETTINGS_KEY))) {
            handleUpdate(settings);
            log.info("updated keycloakconfiguration");
        }

        if (query != null && query.contains("logout=true")) {
            prepareLogout(session);
        }
        if (account != null && session.getAttribute(ConfluenceAuthenticator.LOGGED_OUT_KEY) != null) {
            if (handleLogout(account, session)) {
                log.debug("logout successful");

            } else
                log.info("failed logout for user " + account.getToken().getPreferredUsername());
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

        super.doFilter(req, res, chain);
    }

    private boolean handleLogout(KeycloakSecurityContext account, HttpSession session) {
        logSessionAttributes(session);
        session.removeAttribute(ConfluenceAuthenticator.LOGGED_OUT_KEY);
        if (account != null) {
            log.debug("attempting to logout user " + account.getIdToken().getPreferredUsername());
            HttpGet httpGet = new HttpGet();
            httpGet.setURI(UriBuilder.fromUri(authServer + "/realms/" + realm + "/protocol" +
                    "/openid-connect/logout?id_token_hint=" + account.getIdTokenString()).build());
            log.debug("trying get with " + httpGet.getURI());
            session.removeAttribute(KeycloakSecurityContext.class.getName());

            try (CloseableHttpClient client = HttpClientBuilder.create().build()) {
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
        log.debug("preparing logout");
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
            log.debug("ignoring this request due to queryparam 'noSSO'");
            return true;
        }
        String uri = request.getRequestURI();
        if (uri.contains("/rest")) {
            log.info("ignoring the request because its a REST call");
            return true;
        }

        if (uri.contains("/download/")) {
            log.debug("confluence trying to get some ressources, ignoring the request");
            return true;
        }
        if (uri.contains("/dologin.action")) {
            log.debug("confluence is processing the login request, ignoring");
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

    private void handleUpdate(PluginSettings config) {


        config.remove(ConfigServlet.UPDATED_SETTINGS_KEY);


        try (InputStream is = filterConfiguration.getServletContext().getResourceAsStream("/keycloak.json")) {
            realm = config.get(ConfigServlet.REALM) != null ? (String) config.get(ConfigServlet.REALM) : realm;
            authServer = config.get(ConfigServlet.AUTH_SERVER_URL) != null ? (String) config.get(ConfigServlet.AUTH_SERVER_URL) : authServer;
            resource = config.get(ConfigServlet.RESOURCE) != null ? (String) config.get(ConfigServlet.RESOURCE) : resource;

            AdapterConfig adapterConfig = KeycloakDeploymentBuilder.loadAdapterConfig(is);

            String secret = (String) config.get(ConfigServlet.SECRET);
            Map<String, Object> credentials = adapterConfig.getCredentials();
            credentials.put("secret", secret);

            String realmPublicKey = (String) config.get(ConfigServlet.REALM_PUBLIC_KEY);

            String ssl = (String) config.get(ConfigServlet.SSL_REQUIRED);

            int confidentialPort;
            try {
                confidentialPort = Integer.parseInt((String) config.get(ConfigServlet.CONFIDENTIAL_PORT));
            } catch (NumberFormatException e) {
                confidentialPort = 8443;
            }

            //defaults to false
            boolean enableCors = Boolean.valueOf((String) config.get(ConfigServlet.ENABLE_CORS));

            int poolSize;
            try {
                poolSize = Integer.parseInt((String) config.get(ConfigServlet.CONNECTION_POOL_SIZE));
            } catch (NumberFormatException e) {
                //default value from Keycloak documentation
                poolSize = 20;
            }

            String proxy = config.get(ConfigServlet.PROXY_URL) != null ?
                    (String) config.get(ConfigServlet.PROXY_URL) : adapterConfig.getProxyUrl();

            String truststore = config.get(ConfigServlet.TRUSTSTORE) != null ?
                    (String) config.get(ConfigServlet.TRUSTSTORE) : adapterConfig.getTruststore();

            String truststorePassword = config.get(ConfigServlet.TRUSTSTORE_PASSWORD) != null ?
                    (String) config.get(ConfigServlet.TRUSTSTORE_PASSWORD) : adapterConfig.getTruststorePassword();

            String clientKeystore = (String) config.get(ConfigServlet.CLIENT_KEYSTORE);

            int registerNodePeriod;
            try {
                registerNodePeriod = Integer.parseInt((String) config.get(ConfigServlet.REGISTER_NODE_PERIOD));
            } catch (NumberFormatException e) {
                registerNodePeriod = 60;
            }

            String tokenStore = config.get(ConfigServlet.TOKEN_STORE) != null ?
                    (String) config.get(ConfigServlet.TOKEN_STORE) : "Session";

            String principalAttribute = config.get(ConfigServlet.PRINCIPAL_ATTRIBUTE) != null ?
                    (String) config.get(ConfigServlet.PRINCIPAL_ATTRIBUTE) : "sub";

            int minTimeToLive;
            try {
                minTimeToLive = Integer.parseInt((String) config.get(ConfigServlet.TOKEN_MINIMUM_TIME_TO_LIVE));
            } catch (NumberFormatException e) {
                minTimeToLive = 0;
            }

            int timeBetweenJWKS;
            try {
                timeBetweenJWKS = Integer.parseInt((String) config.get(ConfigServlet.MIN_TIME_BETWEEN_JWKS_REQUEST));
            } catch (NumberFormatException e) {
                timeBetweenJWKS = 10;
            }

            int keyCacheTTL;
            try {
                keyCacheTTL = Integer.parseInt((String) config.get(ConfigServlet.PUBLIC_KEY_CACHE_TTL));
            } catch (NumberFormatException e) {
                keyCacheTTL = 86400;
            }


            /*order is important here */
            adapterConfig.setRealm(realm);
            adapterConfig.setResource(resource);
            if (!StringUtils.isEmpty(realmPublicKey))
                adapterConfig.setRealmKey(realmPublicKey);
            else
                adapterConfig.setRealmKey(null);
            adapterConfig.setAuthServerUrl(authServer);
            adapterConfig.setSslRequired(ssl);
            adapterConfig.setUseResourceRoleMappings(Boolean.valueOf((String) config.get(ConfigServlet.USE_RESOURCE_ROLE_MAPPINGS)));
            adapterConfig.setConfidentialPort(confidentialPort);
            adapterConfig.setPublicClient(Boolean.valueOf((String) config.get(ConfigServlet.PUBLIC_CLIENT)));

            adapterConfig.setCors(enableCors);
            if (enableCors) {
                int corsMaxAge;
                try {
                    corsMaxAge = Integer.parseInt((String) config.get(ConfigServlet.CORS_MAX_AGE));
                } catch (NumberFormatException e) {
                    corsMaxAge = 20;
                }
                String allowedMethods = config.get(ConfigServlet.CORS_ALLOWED_METHODS) != null ?
                        (String) config.get(ConfigServlet.CORS_ALLOWED_METHODS) : adapterConfig.getCorsAllowedMethods();
                String allowedHeaders = config.get(ConfigServlet.CORS_ALLOWED_HEADERS) != null ?
                        (String) config.get(ConfigServlet.CORS_ALLOWED_HEADERS) : adapterConfig.getCorsAllowedHeaders();
                String exposedHeaders = config.get((ConfigServlet.CORS_EXPOSED_HEADERS)) != null ?
                        (String) config.get(ConfigServlet.CORS_EXPOSED_HEADERS) : adapterConfig.getCorsExposedHeaders();

                adapterConfig.setCorsMaxAge(corsMaxAge);
                adapterConfig.setCorsAllowedMethods(allowedMethods);
                adapterConfig.setCorsAllowedHeaders(allowedHeaders);
                adapterConfig.setCorsExposedHeaders(exposedHeaders);
            }

            adapterConfig.setBearerOnly(Boolean.valueOf((String) config.get(ConfigServlet.BEARER_ONLY)));
            adapterConfig.setAutodetectBearerOnly(Boolean.valueOf((String) config.get(ConfigServlet.AUTODETECT_BEARER_ONLY)));
            adapterConfig.setEnableBasicAuth(Boolean.valueOf((String) config.get(ConfigServlet.ENABLE_BASIC_AUTH)));
            adapterConfig.setExposeToken(Boolean.valueOf((String) config.get(ConfigServlet.EXPOSE_TOKEN)));
            adapterConfig.setCredentials(credentials);
            adapterConfig.setConnectionPoolSize(poolSize);
            adapterConfig.setDisableTrustManager(Boolean.valueOf(ConfigServlet.DISABLE_TRUST_MANAGER));
            adapterConfig.setAllowAnyHostname(Boolean.valueOf(ConfigServlet.ALLOW_ANY_HOSTNAME));
            if (!StringUtils.isEmpty(proxy))
                adapterConfig.setProxyUrl(proxy);
            else
                adapterConfig.setProxyUrl(null);
            if (!StringUtils.isEmpty(truststore))
                adapterConfig.setTruststore(truststore);
            else
                adapterConfig.setTruststore(null);
            if (!StringUtils.isEmpty(truststorePassword))
                adapterConfig.setTruststorePassword(truststorePassword);
            else
                adapterConfig.setTruststore(null);
            if (!StringUtils.isEmpty(clientKeystore)) {
                adapterConfig.setClientKeystore(clientKeystore);
                if (!StringUtils.isEmpty((String) config.get(ConfigServlet.CLIENT_KEYSTORE_PASSWORD)))
                    adapterConfig.setClientKeystorePassword((String) config.get(ConfigServlet.CLIENT_KEYSTORE_PASSWORD));
                if (!StringUtils.isEmpty((String) config.get(ConfigServlet.CLIENT_KEY_PASSWORD)))
                    adapterConfig.setClientKeyPassword((String) config.get(ConfigServlet.CLIENT_KEY_PASSWORD));
            } else
                adapterConfig.setClientKeystore(null);

            adapterConfig.setAlwaysRefreshToken(Boolean.valueOf((String) config.get(ConfigServlet.ALWAYS_REFRESH_TOKEN)));
            adapterConfig.setRegisterNodeAtStartup(Boolean.valueOf((String) config.get(ConfigServlet.REGISTER_NODE_AT_STARTUP)));
            adapterConfig.setRegisterNodePeriod(registerNodePeriod);
            adapterConfig.setTokenStore(tokenStore);
            if (tokenStore.equalsIgnoreCase("Cookie")) {
                adapterConfig.setTokenCookiePath((String) config.get(ConfigServlet.TOKEN_COOKIE_PATH));
            }
            adapterConfig.setPrincipalAttribute(principalAttribute);
            adapterConfig.setTurnOffChangeSessionIdOnLogin(Boolean.valueOf((String) config.get(ConfigServlet.TURN_OFF_CHANGE_SESSION_ID_ON_LOGIN)));
            adapterConfig.setTokenMinimumTimeToLive(minTimeToLive);
            adapterConfig.setMinTimeBetweenJwksRequests(timeBetweenJWKS);
            adapterConfig.setPublicKeyCacheTtl(keyCacheTTL);
            adapterConfig.setVerifyTokenAudience(Boolean.valueOf((String) config.get(ConfigServlet.VERIFY_AUDIENCE)));

            KeycloakDeployment ment = KeycloakDeploymentBuilder.build(adapterConfig);
            deploymentContext = new AdapterDeploymentContext(ment);
            log.warn("updated settings");
        } catch (Exception e) {
            log.warn("failed during updated due to " + e.getMessage());
            config.put(EXCEPTION_DURING_UPDATE, e.getMessage());
        }


    }

    private void initFromConfig(AdapterConfig config, PluginSettings toStore) {

        log.warn("Started initial configuration");
        toStore.put(ConfigServlet.REALM, config.getRealm());
        toStore.put(ConfigServlet.RESOURCE, config.getResource());
        toStore.put(ConfigServlet.REALM_PUBLIC_KEY, config.getRealmKey());
        toStore.put(ConfigServlet.AUTH_SERVER_URL, config.getAuthServerUrl());
        toStore.put(ConfigServlet.SSL_REQUIRED, config.getSslRequired());
        toStore.put(ConfigServlet.CONFIDENTIAL_PORT, getString(config.getConfidentialPort()));
        toStore.put(ConfigServlet.USE_RESOURCE_ROLE_MAPPINGS, getString(config.isUseResourceRoleMappings()));
        toStore.put(ConfigServlet.PUBLIC_CLIENT, getString(config.isPublicClient()));
        log.warn("setting CORS options");
        toStore.put(ConfigServlet.ENABLE_CORS, getString(config.isCors()));
        toStore.put(ConfigServlet.CORS_ALLOWED_HEADERS, config.getCorsAllowedHeaders());
        toStore.put(ConfigServlet.CORS_ALLOWED_METHODS, config.getCorsAllowedMethods());
        toStore.put(ConfigServlet.CORS_EXPOSED_HEADERS, config.getCorsExposedHeaders());
        toStore.put(ConfigServlet.CORS_MAX_AGE, getString(config.getCorsMaxAge()));
        toStore.put(ConfigServlet.BEARER_ONLY, getString(config.isBearerOnly()));
        toStore.put(ConfigServlet.AUTODETECT_BEARER_ONLY, getString(config.isAutodetectBearerOnly()));
        toStore.put(ConfigServlet.ENABLE_BASIC_AUTH, getString(config.isEnableBasicAuth()));
        toStore.put(ConfigServlet.EXPOSE_TOKEN, getString(config.isExposeToken()));
        toStore.put(ConfigServlet.SECRET, (String) config.getCredentials().get("secret"));
        toStore.put(ConfigServlet.CONNECTION_POOL_SIZE, getString(config.getConnectionPoolSize()));
        toStore.put(ConfigServlet.DISABLE_TRUST_MANAGER, getString(config.isDisableTrustManager()));
        toStore.put(ConfigServlet.ALLOW_ANY_HOSTNAME, getString(config.isAllowAnyHostname()));
        toStore.put(ConfigServlet.PROXY_URL, config.getProxyUrl());
        log.warn("setting truststore stuff");
        toStore.put(ConfigServlet.TRUSTSTORE, config.getTruststore());
        toStore.put(ConfigServlet.TRUSTSTORE_PASSWORD, config.getTruststorePassword());
        toStore.put(ConfigServlet.CLIENT_KEYSTORE, config.getClientKeystore());
        toStore.put(ConfigServlet.CLIENT_KEYSTORE_PASSWORD, config.getClientKeystorePassword());
        toStore.put(ConfigServlet.CLIENT_KEY_PASSWORD, config.getClientKeyPassword());
        toStore.put(ConfigServlet.ALWAYS_REFRESH_TOKEN, getString(config.isAlwaysRefreshToken()));
        toStore.put(ConfigServlet.REGISTER_NODE_PERIOD, getString(config.getRegisterNodePeriod()));
        toStore.put(ConfigServlet.REGISTER_NODE_AT_STARTUP, getString(config.isRegisterNodeAtStartup()));
        toStore.put(ConfigServlet.TOKEN_STORE, config.getTokenStore());
        toStore.put(ConfigServlet.TOKEN_COOKIE_PATH, config.getTokenCookiePath());
        toStore.put(ConfigServlet.PRINCIPAL_ATTRIBUTE, config.getPrincipalAttribute());
        toStore.put(ConfigServlet.TURN_OFF_CHANGE_SESSION_ID_ON_LOGIN, getString(config.getTurnOffChangeSessionIdOnLogin()));
        toStore.put(ConfigServlet.TOKEN_MINIMUM_TIME_TO_LIVE, getString(config.getTokenMinimumTimeToLive()));
        toStore.put(ConfigServlet.MIN_TIME_BETWEEN_JWKS_REQUEST, getString(config.getMinTimeBetweenJwksRequests()));
        toStore.put(ConfigServlet.PUBLIC_KEY_CACHE_TTL, getString(config.getPublicKeyCacheTtl()));
        toStore.put(ConfigServlet.IGNORE_OAUTH_QUERY_PARAM, getString(config.isIgnoreOAuthQueryParameter()));
        toStore.put(ConfigServlet.VERIFY_AUDIENCE, getString(config.isVerifyTokenAudience()));
    }

    private String getString(Integer number) {

        if (number == null) {
            number = -1;
        }
        return number.toString();
    }

    private String getString(Boolean bool) {

        if (bool == null)
            bool = Boolean.FALSE;
        return bool.toString();
    }

    @Override
    public void destroy() {

        super.destroy();
        PluginSettings settings = factory.createSettingsForKey(SETTINGS_KEY);
        settings.remove(SETTINGS_KEY);
        log.warn("destroyed the filter");
    }

    private UserAccessor getAccessor() {
        return (UserAccessor) ContainerManager.getComponent("userAccessor");
    }
}