/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.identity.integration.test.restclients;

import io.restassured.http.ContentType;
import org.apache.commons.codec.binary.Base64;
import org.apache.http.Header;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.message.BasicHeader;
import org.apache.http.util.EntityUtils;
import org.json.simple.JSONObject;
import org.testng.Assert;
import org.wso2.carbon.automation.engine.context.beans.Tenant;
import org.wso2.identity.integration.common.utils.ISIntegrationTest;
import org.wso2.identity.integration.test.rest.api.server.notification.template.v1.model.EmailTemplateWithID;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletResponse;

/**
 * Rest client for the Notification Templates API.
 */
public class NotificationTemplatesRestClient extends RestBaseClient {

    private static final String API_SERVER_BASE_PATH = "/api/server/v1";
    private static final String PATH_SEPARATOR = "/";
    private static final String NOTIFICATION_TEMPLATE_PATH = "/notification";
    private static final String EMAIL_PATH = "/email";
    private static final String TEMPLATE_TYPES_PATH = "/template-types";
    private static final String ORG_TEMPLATES_PATH = "/org-templates";
    private static final String RESOLVE_PROPERTY = "resolve";
    private final String tenantDomain;
    private final String username;
    private final String password;
    private final String notificationTemplatesEmailBasePath;
    private final String notificationTemplatesEmailOrgBasePath;

    public NotificationTemplatesRestClient(String baseUrl, Tenant tenantInfo) {

        this.tenantDomain = tenantInfo.getContextUser().getUserDomain();
        this.username = tenantInfo.getContextUser().getUserName();
        this.password = tenantInfo.getContextUser().getPassword();
        this.notificationTemplatesEmailBasePath = baseUrl + ISIntegrationTest.getTenantedRelativePath(
                API_SERVER_BASE_PATH, tenantDomain) + NOTIFICATION_TEMPLATE_PATH + EMAIL_PATH;
        this.notificationTemplatesEmailOrgBasePath = baseUrl + ISIntegrationTest.getTenantedOrgRelativePath(
                API_SERVER_BASE_PATH, tenantDomain) + NOTIFICATION_TEMPLATE_PATH + EMAIL_PATH;
    }

    public JSONObject getEmailOrgTemplate(String templateId, String locale) throws Exception {

        String requestPath = notificationTemplatesEmailBasePath + TEMPLATE_TYPES_PATH + PATH_SEPARATOR + templateId +
                ORG_TEMPLATES_PATH + PATH_SEPARATOR + locale;
        try (CloseableHttpResponse response = getResponseOfHttpGet(requestPath, getHeaders())) {
            return getJSONObject(EntityUtils.toString(response.getEntity()));
        }
    }

    public JSONObject getSubOrgEmailOrgTemplate(String templateId, String locale, String switchedM2MToken,
                                                boolean resolve)
            throws Exception {

        String requestPath = notificationTemplatesEmailOrgBasePath + TEMPLATE_TYPES_PATH + PATH_SEPARATOR + templateId +
                ORG_TEMPLATES_PATH + PATH_SEPARATOR + locale;
        Map<String, String> queryParams = new HashMap<>();
        if (resolve) {
            queryParams.put(RESOLVE_PROPERTY, "true");
        }
        try (CloseableHttpResponse response = getResponseOfHttpGetWithQueryParams(
                requestPath, getHeadersWithBearerToken(switchedM2MToken), queryParams)) {
            return getJSONObject(EntityUtils.toString(response.getEntity()));
        }
    }

    public String addEmailOrgTemplate(String templateId, EmailTemplateWithID emailTemplate) throws IOException {

        String jsonRequest = toJSONString(emailTemplate);
        String requestPath = notificationTemplatesEmailBasePath + TEMPLATE_TYPES_PATH + PATH_SEPARATOR + templateId +
                ORG_TEMPLATES_PATH;
        try (CloseableHttpResponse response = getResponseOfHttpPost(requestPath, jsonRequest, getHeaders())) {
            String[] locationElements = response.getHeaders(LOCATION_HEADER)[0].toString().split(PATH_SEPARATOR);
            return locationElements[locationElements.length - 2];
        }
    }

    public String addSubOrgEmailOrgTemplate(String templateId, EmailTemplateWithID emailTemplate,
                                            String switchedM2MToken) throws IOException {

        String jsonRequest = toJSONString(emailTemplate);
        String requestPath = notificationTemplatesEmailOrgBasePath + TEMPLATE_TYPES_PATH + PATH_SEPARATOR + templateId +
                ORG_TEMPLATES_PATH;
        try (CloseableHttpResponse response =
                     getResponseOfHttpPost(requestPath, jsonRequest, getHeadersWithBearerToken(switchedM2MToken))) {
            String[] locationElements = response.getHeaders(LOCATION_HEADER)[0].toString().split(PATH_SEPARATOR);
            return locationElements[locationElements.length - 2];
        }
    }

    public void updateEmailOrgTemplate(String templateId, String locale, EmailTemplateWithID emailTemplate)
            throws IOException {

        String jsonRequest = toJSONString(emailTemplate);
        String requestPath = notificationTemplatesEmailBasePath + TEMPLATE_TYPES_PATH + PATH_SEPARATOR + templateId +
                ORG_TEMPLATES_PATH + PATH_SEPARATOR + locale;
        try (CloseableHttpResponse response = getResponseOfHttpPut(requestPath, jsonRequest, getHeaders())) {
            Assert.assertEquals(response.getStatusLine().getStatusCode(), HttpServletResponse.SC_OK,
                    "Email org template update failed.");
        }
    }

    public void updateSubOrgEmailOrgTemplate(String templateId, String locale, EmailTemplateWithID emailTemplate,
                                             String switchedM2MToken) throws IOException {

        String jsonRequest = toJSONString(emailTemplate);
        String requestPath = notificationTemplatesEmailOrgBasePath + TEMPLATE_TYPES_PATH + PATH_SEPARATOR + templateId +
                ORG_TEMPLATES_PATH + PATH_SEPARATOR + locale;
        try (CloseableHttpResponse response = getResponseOfHttpPut(requestPath, jsonRequest,
                getHeadersWithBearerToken(switchedM2MToken))) {
            Assert.assertEquals(response.getStatusLine().getStatusCode(), HttpServletResponse.SC_OK,
                    "Email org template update failed.");
        }
    }

    public void deleteEmailOrgTemplate(String templateId, String locale) throws IOException {

        String requestPath = notificationTemplatesEmailBasePath + TEMPLATE_TYPES_PATH + PATH_SEPARATOR + templateId +
                ORG_TEMPLATES_PATH + PATH_SEPARATOR + locale;
        try (CloseableHttpResponse response = getResponseOfHttpDelete(requestPath, getHeaders())) {
            Assert.assertEquals(response.getStatusLine().getStatusCode(), HttpServletResponse.SC_NO_CONTENT,
                    "Email org template delete failed.");
        }
    }

    public void deleteSubOrgEmailOrgTemplate(String templateId, String locale, String switchedM2MToken) throws IOException {

        String requestPath = notificationTemplatesEmailOrgBasePath + TEMPLATE_TYPES_PATH + PATH_SEPARATOR + templateId +
                ORG_TEMPLATES_PATH + PATH_SEPARATOR + locale;
        try (CloseableHttpResponse response = getResponseOfHttpDelete(requestPath, getHeadersWithBearerToken(switchedM2MToken))) {
            Assert.assertEquals(response.getStatusLine().getStatusCode(), HttpServletResponse.SC_NO_CONTENT,
                    "Email org template delete failed.");
        }
    }

    private Header[] getHeaders() {

        Header[] headerList = new Header[2];
        headerList[0] = new BasicHeader(AUTHORIZATION_ATTRIBUTE, BASIC_AUTHORIZATION_ATTRIBUTE +
                Base64.encodeBase64String((username + ":" + password).getBytes()).trim());
        headerList[1] = new BasicHeader(CONTENT_TYPE_ATTRIBUTE, String.valueOf(ContentType.JSON));

        return headerList;
    }

    private Header[] getHeadersWithBearerToken(String accessToken) {

        Header[] headerList = new Header[2];
        headerList[0] = new BasicHeader(AUTHORIZATION_ATTRIBUTE, BEARER_TOKEN_AUTHORIZATION_ATTRIBUTE + accessToken);
        headerList[1] = new BasicHeader(CONTENT_TYPE_ATTRIBUTE, String.valueOf(ContentType.JSON));

        return headerList;
    }
}
