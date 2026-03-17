/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.identity.integration.test.oauth2;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.Header;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.config.Lookup;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.cookie.CookieSpecProvider;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultRedirectStrategy;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.cookie.RFC6265CookieSpecProvider;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.json.simple.JSONObject;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Factory;
import org.testng.annotations.Test;
import org.wso2.carbon.automation.engine.context.TestUserMode;
import org.wso2.identity.integration.test.rest.api.common.RESTTestBase;
import org.wso2.identity.integration.test.rest.api.server.application.management.v1.model.AdvancedApplicationConfiguration;
import org.wso2.identity.integration.test.rest.api.server.application.management.v1.model.ApplicationModel;
import org.wso2.identity.integration.test.rest.api.server.application.management.v1.model.ApplicationResponseModel;
import org.wso2.identity.integration.test.rest.api.server.application.management.v1.model.ApplicationSharePOSTRequest;
import org.wso2.identity.integration.test.rest.api.server.application.management.v1.model.InboundProtocols;
import org.wso2.identity.integration.test.rest.api.server.application.management.v1.model.OpenIDConnectConfiguration;
import org.wso2.identity.integration.test.rest.api.user.common.model.Email;
import org.wso2.identity.integration.test.rest.api.user.common.model.UserObject;
import org.wso2.identity.integration.test.restclients.OAuth2RestClient;
import org.wso2.identity.integration.test.restclients.OrgMgtRestClient;
import org.wso2.identity.integration.test.restclients.SCIM2RestClient;
import org.wso2.identity.integration.test.utils.DataExtractUtil;
import org.wso2.identity.integration.test.utils.OAuth2Constant;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.wso2.identity.integration.test.utils.OAuth2Constant.ACCESS_TOKEN_ENDPOINT;
import static org.wso2.identity.integration.test.utils.OAuth2Constant.AUTHORIZE_ENDPOINT_URL;
import static org.wso2.identity.integration.test.utils.OAuth2Constant.CALLBACK_URL;
import static org.wso2.identity.integration.test.utils.OAuth2Constant.COMMON_AUTH_URL;
import static org.wso2.identity.integration.test.utils.OAuth2Constant.HTTP_RESPONSE_HEADER_LOCATION;
import static org.wso2.identity.integration.test.utils.OAuth2Constant.OAUTH2_GRANT_TYPE_AUTHORIZATION_CODE;

/**
 * Integration test for the Enhanced B2B Login feature.
 *
 * <p>The enhanced B2B login flow uses the {@code Organization Identifier Handler} authenticator.
 * Instead of explicit internal federation (as in the classic {@code OrganizationAuthenticator}),
 * it populates org login details directly into the authentication context and lets the framework
 * switch to the sub-org context without an extra federation round-trip.</p>
 *
 * <p>The feature is enabled per-application via the {@code enhancedOrgAuthenticationEnabled}
 * boolean property on the application. The authorization code flow uses Path B (o-path):
 * all requests go through {@code /t/<rootTenant>/o/<orgId>/...}.</p>
 */
public class EnhancedB2BLoginTestCase extends OAuth2ServiceAbstractIntegrationTest {

    private static final String APP_NAME = "EnhancedB2BLoginApp";
    private static final String MGT_APP_AUTHORIZED_API_RESOURCES = "management-app-authorized-apis.json";
    private static final String ORG_END_USER_USERNAME = "enhancedB2BUser";
    private static final String ORG_END_USER_PASSWORD = "EnhancedB2BUser@wso2";
    private static final String ORG_END_USER_EMAIL = "enhancedB2BUser@wso2.com";

    private final TestUserMode userMode;
    private final String organizationName;
    private final String organizationHandle;

    private CloseableHttpClient client;
    private SCIM2RestClient scim2RestClient;
    private OrgMgtRestClient orgMgtRestClient;
    private OAuth2RestClient oAuth2RestClient;

    private String organizationId;
    private String orgUserId;
    private String rootApplicationId;
    private String clientId;
    private String clientSecret;
    private String switchedM2MToken;
    private String sessionDataKey;
    private String authorizationCode;
    private String accessToken;

    @DataProvider(name = "configProvider")
    public static Object[][] configProvider() {

        return new Object[][]{
                {TestUserMode.SUPER_TENANT_ADMIN, "enhancedstborg", "enhancedstborg"},
                {TestUserMode.TENANT_ADMIN, "enhancedb2borg2", "enhancedb2borg2"}};
    }

    @Factory(dataProvider = "configProvider")
    public EnhancedB2BLoginTestCase(TestUserMode userMode, String orgName, String orgHandle) {

        this.userMode = userMode;
        this.organizationName = orgName;
        this.organizationHandle = orgHandle;
    }

    // =========================================================================
    // Setup
    // =========================================================================

    @Test(priority = 1)
    public void testInit() throws Exception {

        super.init(userMode);

        Lookup<CookieSpecProvider> cookieSpecRegistry = RegistryBuilder.<CookieSpecProvider>create()
                .register(CookieSpecs.DEFAULT, new RFC6265CookieSpecProvider())
                .build();
        client = HttpClientBuilder.create()
                .setDefaultCookieStore(new BasicCookieStore())
                .setDefaultRequestConfig(RequestConfig.custom().setCookieSpec(CookieSpecs.DEFAULT).build())
                .setDefaultCookieSpecRegistry(cookieSpecRegistry)
                .setRedirectStrategy(new DefaultRedirectStrategy() {
                    @Override
                    protected boolean isRedirectable(String method) {
                        return false;
                    }
                })
                .build();

        scim2RestClient = new SCIM2RestClient(serverURL, tenantInfo);
        oAuth2RestClient = new OAuth2RestClient(serverURL, tenantInfo);
        orgMgtRestClient = new OrgMgtRestClient(isServer, tenantInfo, serverURL,
                new org.json.JSONObject(RESTTestBase.readResource(MGT_APP_AUTHORIZED_API_RESOURCES, this.getClass())));

        // Delete any resources left from a previous failed run before starting.
        deletePreExistingResources();
    }

    @Test(priority = 2, dependsOnMethods = "testInit")
    public void testCreateEnhancedB2BApplication() throws Exception {

        OpenIDConnectConfiguration oidcConfig = new OpenIDConnectConfiguration();
        oidcConfig.addGrantTypesItem(OAUTH2_GRANT_TYPE_AUTHORIZATION_CODE);
        oidcConfig.addCallbackURLsItem(CALLBACK_URL);

        InboundProtocols inboundProtocols = new InboundProtocols();
        inboundProtocols.setOidc(oidcConfig);

        ApplicationModel app = new ApplicationModel()
                .name(APP_NAME)
                .enhancedOrgAuthenticationEnabled(true)
                .inboundProtocolConfiguration(inboundProtocols)
                .advancedConfigurations(new AdvancedApplicationConfiguration()
                        .skipLoginConsent(true)
                        .skipLogoutConsent(true));

        rootApplicationId = oAuth2RestClient.createApplication(app);
        assertNotNull(rootApplicationId, "Root application ID should not be null.");

        OpenIDConnectConfiguration createdOidcConfig = oAuth2RestClient.getOIDCInboundDetails(rootApplicationId);
        assertNotNull(createdOidcConfig, "OIDC configuration should not be null.");
        clientId = createdOidcConfig.getClientId();
        clientSecret = createdOidcConfig.getClientSecret();
        assertNotNull(clientId, "Client ID should not be null.");
        assertNotNull(clientSecret, "Client secret should not be null.");
    }

    @Test(priority = 3, dependsOnMethods = "testCreateEnhancedB2BApplication")
    public void testCreateSubOrganization() throws Exception {

        String m2mToken = orgMgtRestClient.getM2MAccessToken();
        organizationId = orgMgtRestClient.addOrganizationWithToken(organizationName, organizationHandle, m2mToken);
        assertNotNull(organizationId, "Organization ID should not be null.");
    }

    @Test(priority = 4, dependsOnMethods = "testCreateSubOrganization")
    public void testShareApplicationToSubOrg() throws Exception {

        ApplicationSharePOSTRequest shareRequest = new ApplicationSharePOSTRequest();
        shareRequest.setShareWithAllChildren(true);
        oAuth2RestClient.shareApplication(rootApplicationId, shareRequest);

        // Allow time for the async share operation to complete.
        Thread.sleep(5000);
    }

    @Test(priority = 5, dependsOnMethods = "testShareApplicationToSubOrg")
    public void testCreateSubOrgUser() throws Exception {

        switchedM2MToken = orgMgtRestClient.switchM2MToken(organizationId);
        assertNotNull(switchedM2MToken, "Switched M2M token should not be null.");

        UserObject endUser = new UserObject();
        endUser.setUserName(ORG_END_USER_USERNAME);
        endUser.setPassword(ORG_END_USER_PASSWORD);
        endUser.addEmail(new Email().value(ORG_END_USER_EMAIL));

        orgUserId = scim2RestClient.createSubOrgUser(endUser, switchedM2MToken);
        assertNotNull(orgUserId, "Sub-org user ID should not be null.");
    }

    // =========================================================================
    // Happy Path Login (priority 6–9)
    // =========================================================================

    @Test(priority = 6, dependsOnMethods = "testCreateSubOrgUser")
    public void testSendAuthorizeRequest() throws Exception {

        List<NameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair("response_type", "code"));
        params.add(new BasicNameValuePair("client_id", clientId));
        params.add(new BasicNameValuePair("redirect_uri", CALLBACK_URL));
        params.add(new BasicNameValuePair("scope", "openid"));

        // Path B: /t/<rootTenant>/o/<orgId>/oauth2/authorize — skips org discovery entirely.
        HttpResponse response = sendPostRequestWithParameters(client, params, getOPathURL(AUTHORIZE_ENDPOINT_URL));

        Header locationHeader = response.getFirstHeader(HTTP_RESPONSE_HEADER_LOCATION);
        assertNotNull(locationHeader, "Location header expected for authorize request is not available.");
        EntityUtils.consume(response.getEntity());

        // Follow redirect to the sub-org login page.
        response = sendGetRequest(client, locationHeader.getValue());

        Map<String, Integer> keyPositionMap = new HashMap<>(1);
        keyPositionMap.put("name=\"sessionDataKey\"", 1);
        List<DataExtractUtil.KeyValue> keyValues = DataExtractUtil.extractDataFromResponse(response, keyPositionMap);
        assertNotNull(keyValues, "sessionDataKey not found on login page.");

        sessionDataKey = keyValues.get(0).getValue();
        assertNotNull(sessionDataKey, "Session data key should not be null.");
        EntityUtils.consume(response.getEntity());
    }

    @Test(priority = 7, dependsOnMethods = "testSendAuthorizeRequest")
    public void testSendLoginPost() throws Exception {

        // POST credentials to the sub-org commonauth endpoint (o-path).
        List<NameValuePair> urlParameters = new ArrayList<>();
        urlParameters.add(new BasicNameValuePair("username", ORG_END_USER_USERNAME));
        urlParameters.add(new BasicNameValuePair("password", ORG_END_USER_PASSWORD));
        urlParameters.add(new BasicNameValuePair("sessionDataKey", sessionDataKey));

        HttpResponse response = sendPostRequestWithParameters(client, urlParameters, getOPathURL(COMMON_AUTH_URL));

        Header locationHeader = response.getFirstHeader(HTTP_RESPONSE_HEADER_LOCATION);
        assertNotNull(locationHeader, "Location header expected post login is not available.");
        EntityUtils.consume(response.getEntity());

        response = sendGetRequest(client, locationHeader.getValue());
        locationHeader = response.getFirstHeader(HTTP_RESPONSE_HEADER_LOCATION);
        EntityUtils.consume(response.getEntity());

        // Follow additional redirects until we reach the callback URL with the auth code.
        while (locationHeader != null && !locationHeader.getValue().contains(CALLBACK_URL.split("\\?")[0])) {
            response = sendGetRequest(client, locationHeader.getValue());
            locationHeader = response.getFirstHeader(HTTP_RESPONSE_HEADER_LOCATION);
            EntityUtils.consume(response.getEntity());
        }

        assertNotNull(locationHeader, "Redirection URL to the application with authorization code is null.");
        authorizationCode = getAuthorizationCodeFromURL(locationHeader.getValue());
        assertNotNull(authorizationCode, "Authorization code should not be null.");
    }

    @Test(priority = 8, dependsOnMethods = "testSendLoginPost")
    public void testGetAccessToken() throws Exception {

        List<NameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair("code", authorizationCode));
        params.add(new BasicNameValuePair("grant_type", OAUTH2_GRANT_TYPE_AUTHORIZATION_CODE));
        params.add(new BasicNameValuePair("redirect_uri", CALLBACK_URL));

        List<org.apache.http.Header> headers = new ArrayList<>();
        headers.add(new org.apache.http.message.BasicHeader("Authorization",
                "Basic " + getBase64EncodedString(clientId, clientSecret)));
        headers.add(new org.apache.http.message.BasicHeader("Content-Type",
                "application/x-www-form-urlencoded;charset=UTF-8"));
        headers.add(new org.apache.http.message.BasicHeader("User-Agent", OAuth2Constant.USER_AGENT));

        HttpResponse response = sendPostRequest(client, headers, params, getOPathURL(ACCESS_TOKEN_ENDPOINT));
        assertNotNull(response, "Token endpoint response should not be null.");

        String responseBody = EntityUtils.toString(response.getEntity(), "UTF-8");
        org.json.JSONObject jsonResponse = new org.json.JSONObject(responseBody);

        assertTrue(jsonResponse.has("access_token"), "access_token is missing from token response.");
        accessToken = jsonResponse.getString("access_token");
        assertNotNull(accessToken, "Access token should not be null.");
    }

    @Test(priority = 9, dependsOnMethods = "testGetAccessToken")
    public void testIntrospectAccessToken() throws Exception {

        String introspectUrl = OAuth2Constant.INTRO_SPEC_ENDPOINT.replaceFirst(
                "(https?://[^/]+)(/.+)", "$1/t/" + tenantInfo.getDomain() + "$2");
        JSONObject introspectionResponse = introspectTokenWithTenant(client, accessToken,
                introspectUrl, tenantInfo.getTenantAdmin().getUserName(),
                tenantInfo.getTenantAdmin().getPassword());

        assertNotNull(introspectionResponse, "Introspection response should not be null.");
        assertTrue(introspectionResponse.containsKey("active"),
                "active field is missing from introspection response.");
        assertTrue((Boolean) introspectionResponse.get("active"), "Token should be active.");

        assertTrue(introspectionResponse.containsKey("username"),
                "username claim is missing from introspection response.");

        assertTrue(
                introspectionResponse.containsKey("org_id") || introspectionResponse.containsKey("org_name"),
                "Neither org_id nor org_name claim is present in the introspection response.");
    }

    // =========================================================================
    // Negative Cases (priority 10–11)
    // =========================================================================

    @Test(priority = 10, dependsOnMethods = "testIntrospectAccessToken")
    public void testLoginWithInvalidPassword() throws Exception {

        // Use a fresh client without session cookies so the authorize request always shows the login page.
        Lookup<CookieSpecProvider> cookieSpecRegistry = RegistryBuilder.<CookieSpecProvider>create()
                .register(CookieSpecs.DEFAULT, new RFC6265CookieSpecProvider())
                .build();
        CloseableHttpClient freshClient = HttpClientBuilder.create()
                .setDefaultCookieStore(new BasicCookieStore())
                .setDefaultRequestConfig(RequestConfig.custom().setCookieSpec(CookieSpecs.DEFAULT).build())
                .setDefaultCookieSpecRegistry(cookieSpecRegistry)
                .setRedirectStrategy(new DefaultRedirectStrategy() {
                    @Override
                    protected boolean isRedirectable(String method) {
                        return false;
                    }
                })
                .build();

        try {
        // Get a fresh session data key via a new authorize request.
        List<NameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair("response_type", "code"));
        params.add(new BasicNameValuePair("client_id", clientId));
        params.add(new BasicNameValuePair("redirect_uri", CALLBACK_URL));
        params.add(new BasicNameValuePair("scope", "openid"));

        HttpResponse authorizeResponse = sendPostRequestWithParameters(freshClient, params,
                getOPathURL(AUTHORIZE_ENDPOINT_URL));
        Header locationHeader = authorizeResponse.getFirstHeader(HTTP_RESPONSE_HEADER_LOCATION);
        assertNotNull(locationHeader, "Location header for invalid-password authorize request is not available.");
        EntityUtils.consume(authorizeResponse.getEntity());

        HttpResponse loginPageResponse = sendGetRequest(freshClient, locationHeader.getValue());
        Map<String, Integer> keyPositionMap = new HashMap<>(1);
        keyPositionMap.put("name=\"sessionDataKey\"", 1);
        List<DataExtractUtil.KeyValue> keyValues =
                DataExtractUtil.extractDataFromResponse(loginPageResponse, keyPositionMap);
        assertNotNull(keyValues, "sessionDataKey not found for negative test.");
        EntityUtils.consume(loginPageResponse.getEntity());

        String freshSessionDataKey = keyValues.get(0).getValue();
        assertNotNull(freshSessionDataKey, "Fresh session data key should not be null.");

        // Attempt login with a wrong password.
        List<NameValuePair> urlParameters = new ArrayList<>();
        urlParameters.add(new BasicNameValuePair("username", ORG_END_USER_USERNAME));
        urlParameters.add(new BasicNameValuePair("password", "WrongPassword@123"));
        urlParameters.add(new BasicNameValuePair("sessionDataKey", freshSessionDataKey));

        HttpResponse loginResponse = sendPostRequestWithParameters(freshClient, urlParameters,
                getOPathURL(COMMON_AUTH_URL));
        Header loginLocationHeader = loginResponse.getFirstHeader(HTTP_RESPONSE_HEADER_LOCATION);
        EntityUtils.consume(loginResponse.getEntity());

        // Follow the redirect chain and assert no auth code is issued.
        String location = loginLocationHeader != null ? loginLocationHeader.getValue() : "";
        for (int i = 0; i < 5 && loginLocationHeader != null && !location.contains("code="); i++) {
            HttpResponse followResponse = sendGetRequest(freshClient, location);
            Header nextLocation = followResponse.getFirstHeader(HTTP_RESPONSE_HEADER_LOCATION);
            EntityUtils.consume(followResponse.getEntity());
            if (nextLocation == null) break;
            location = nextLocation.getValue();
        }
        Assert.assertFalse(location.contains("code="),
                "Authorization code should NOT be present when wrong password is used.");
        } finally {
            freshClient.close();
        }
    }

    @Test(priority = 11, dependsOnMethods = "testCreateEnhancedB2BApplication")
    public void testVerifyEnhancedFlagReflectedInAppResponse() throws Exception {

        ApplicationResponseModel appResponse = oAuth2RestClient.getApplication(rootApplicationId);
        assertNotNull(appResponse, "Application response should not be null.");
        assertNotNull(appResponse.getEnhancedOrgAuthenticationEnabled(),
                "enhancedOrgAuthenticationEnabled should not be null in the application response.");
        assertTrue(appResponse.getEnhancedOrgAuthenticationEnabled(),
                "enhancedOrgAuthenticationEnabled should be true for the created application.");
    }

    // =========================================================================
    // Teardown
    // =========================================================================

    @AfterClass(alwaysRun = true)
    public void cleanupTest() throws Exception {

        if (orgUserId != null && switchedM2MToken != null && scim2RestClient != null) {
            scim2RestClient.deleteSubOrgUser(orgUserId, switchedM2MToken);
        }
        if (organizationId != null && orgMgtRestClient != null) {
            orgMgtRestClient.deleteOrganization(organizationId);
        }
        if (rootApplicationId != null && oAuth2RestClient != null) {
            oAuth2RestClient.deleteApplication(rootApplicationId);
        }
        if (client != null) {
            client.close();
        }
        if (scim2RestClient != null) {
            scim2RestClient.closeHttpClient();
        }
        if (oAuth2RestClient != null) {
            oAuth2RestClient.closeHttpClient();
        }
        if (orgMgtRestClient != null) {
            orgMgtRestClient.closeHttpClient();
        }
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /**
     * Builds the o-path URL for the given endpoint constant by inserting
     * {@code /t/<tenant>/o/<orgId>} into the URL.
     *
     * <p>Example: {@code https://localhost:9853/oauth2/authorize}
     * → {@code https://localhost:9853/t/wso2.com/o/<orgId>/oauth2/authorize}</p>
     */
    private String getOPathURL(String endpointUrl) {

        // getTenantQualifiedURL skips the /t/ prefix for carbon.super, so force it explicitly.
        // Result: https://localhost:9853/t/<tenant>/o/<orgId>/<servlet-path>
        String tenantUrl = endpointUrl.replaceFirst(
                "(https?://[^/]+)(/.+)",
                "$1/t/" + tenantInfo.getDomain() + "$2");
        return tenantUrl.replaceFirst("(/t/[^/]+)(/.+)", "$1/o/" + organizationId + "$2");
    }

    /**
     * Deletes any application and organization left over from a previous failed test run.
     */
    private void deletePreExistingResources() {

        try {
            String existingAppId = oAuth2RestClient.getAppIdUsingAppName(APP_NAME);
            if (existingAppId != null && !existingAppId.isEmpty()) {
                log.info("Pre-existing application found (" + existingAppId + "). Deleting before test run.");
                oAuth2RestClient.deleteApplication(existingAppId);
            }
        } catch (Exception e) {
            log.warn("Could not clean up pre-existing application: " + e.getMessage());
        }

        try {
            String existingOrgId = findOrganizationIdByName(organizationName);
            if (existingOrgId != null) {
                log.info("Pre-existing organization found (" + existingOrgId + "). Deleting before test run.");
                orgMgtRestClient.deleteOrganization(existingOrgId);
            }
        } catch (Exception e) {
            log.warn("Could not clean up pre-existing organization: " + e.getMessage());
        }
    }

    /**
     * Queries the organization list API to find an organization's ID by name.
     */
    private String findOrganizationIdByName(String orgName) throws Exception {

        String orgListUrl = getTenantQualifiedURL(serverURL + "api/server/v1/organizations",
                tenantInfo.getDomain()) + "?filter=name%20eq%20" + orgName;

        HttpGet httpGet = new HttpGet(orgListUrl);
        httpGet.setHeader("Authorization", "Basic " + Base64.encodeBase64String(
                (tenantInfo.getTenantAdmin().getUserName() + ":" +
                        tenantInfo.getTenantAdmin().getPassword()).getBytes()).trim());
        httpGet.setHeader("Accept", "application/json");
        httpGet.setHeader("User-Agent", OAuth2Constant.USER_AGENT);

        HttpResponse response = client.execute(httpGet);
        String responseBody = EntityUtils.toString(response.getEntity(), "UTF-8");

        org.json.JSONObject jsonResponse = new org.json.JSONObject(responseBody);
        if (jsonResponse.has("organizations") && jsonResponse.getJSONArray("organizations").length() > 0) {
            return jsonResponse.getJSONArray("organizations").getJSONObject(0).getString("id");
        }
        return null;
    }

    private String getAuthorizationCodeFromURL(String location) {

        URI uri = URI.create(location);
        return URLEncodedUtils.parse(uri, StandardCharsets.UTF_8).stream()
                .filter(param -> "code".equals(param.getName()))
                .map(NameValuePair::getValue)
                .findFirst()
                .orElse(null);
    }
}
