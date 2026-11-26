/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
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

package org.apache.ranger.rest;

import org.apache.ranger.biz.AIInsightsProxy;
import org.apache.ranger.common.ContextUtil;
import org.apache.ranger.common.PropertiesUtil;
import org.apache.ranger.common.RESTErrorUtil;
import org.apache.ranger.credentialapi.CredentialReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Scope;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

/**
 * Read-only access to the AI Insights report produced by the ranger-ai-agent
 * service (RANGER-5278).
 *
 * <p>The browser only ever talks to Ranger Admin, so it is authenticated by the
 * normal Ranger login. This resource then fetches the report from the agent
 * using a service token that never leaves the server. Only system
 * administrators can call it. The agent URL comes from configuration, not from
 * the request.
 */
@Path("ai-insights")
@Component
@Scope("request")
public class AIInsightsREST {
    private static final Logger LOG = LoggerFactory.getLogger(AIInsightsREST.class);

    public static final String PROP_ENABLED          = "ranger.ai.insights.enabled";
    public static final String PROP_URL              = "ranger.ai.insights.url";
    public static final String PROP_TOKEN            = "ranger.ai.insights.token";
    public static final String PROP_TOKEN_ALIAS      = "ranger.ai.insights.credential.alias";
    public static final String PROP_CONNECT_TIMEOUT  = "ranger.ai.insights.connect.timeout.ms";
    public static final String PROP_READ_TIMEOUT     = "ranger.ai.insights.read.timeout.ms";
    public static final String PROP_CREDENTIAL_PATH  = "ranger.credential.provider.path";
    public static final String PROP_KEYSTORE_TYPE    = "ranger.keystore.file.type";
    public static final String DISABLED_JSON         = "{\"enabled\":false}";

    static final int DEFAULT_CONNECT_TIMEOUT_MS = 3000;
    static final int DEFAULT_READ_TIMEOUT_MS    = 10000;

    @Autowired
    RESTErrorUtil restErrorUtil;

    @GET
    @Path("report")
    @Produces(MediaType.APPLICATION_JSON)
    @PreAuthorize("hasRole('ROLE_SYS_ADMIN')")
    public String getReport() {
        if (!Boolean.parseBoolean(trim(property(PROP_ENABLED)))) {
            return DISABLED_JSON;
        }

        LOG.info("AI insights report requested by {}", ContextUtil.getCurrentUserLoginId());

        AIInsightsProxy proxy;

        try {
            proxy = newProxy(trim(property(PROP_URL)), resolveToken(), intProperty(PROP_CONNECT_TIMEOUT, DEFAULT_CONNECT_TIMEOUT_MS), intProperty(PROP_READ_TIMEOUT, DEFAULT_READ_TIMEOUT_MS));
        } catch (IllegalArgumentException e) {
            LOG.error("AI insights is enabled but not configured correctly: {}", e.getMessage());

            // the message below is sent to the browser, so it must not carry configuration details
            throw restErrorUtil.createRESTException(HttpServletResponse.SC_SERVICE_UNAVAILABLE, "AI insights is not configured correctly. See the Ranger Admin log.", false);
        }

        try {
            return proxy.fetchInsightsJson();
        } catch (AIInsightsProxy.UpstreamException e) {
            LOG.error("AI insights service call failed: {}", e.getMessage());

            throw restErrorUtil.createRESTException(HttpServletResponse.SC_BAD_GATEWAY, "AI insights service is unavailable. See the Ranger Admin log.", false);
        }
    }

    // The methods below are overridable so tests do not depend on static Ranger state.

    protected String property(String key) {
        return PropertiesUtil.getProperty(key);
    }

    protected String decryptCredential(String providerPath, String alias, String storeType) {
        return CredentialReader.getDecryptedString(providerPath, alias, storeType);
    }

    protected AIInsightsProxy newProxy(String url, String token, int connectTimeoutMs, int readTimeoutMs) {
        return new AIInsightsProxy(url, token, connectTimeoutMs, readTimeoutMs);
    }

    private String resolveToken() {
        String alias        = trim(property(PROP_TOKEN_ALIAS));
        String providerPath = trim(property(PROP_CREDENTIAL_PATH));

        if (!alias.isEmpty() && !providerPath.isEmpty()) {
            String fromStore = trim(decryptCredential(providerPath, alias, trim(property(PROP_KEYSTORE_TYPE))));

            if (!fromStore.isEmpty() && !"none".equalsIgnoreCase(fromStore)) {
                return fromStore;
            }
        }

        return trim(property(PROP_TOKEN));
    }

    private int intProperty(String key, int defaultValue) {
        String value = trim(property(key));

        if (value.isEmpty()) {
            return defaultValue;
        }

        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            LOG.warn("Ignoring non-numeric value for {}; using {}", key, defaultValue);

            return defaultValue;
        }
    }

    private static String trim(String value) {
        return value == null ? "" : value.trim();
    }
}
