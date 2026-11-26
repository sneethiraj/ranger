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
import org.apache.ranger.common.RESTErrorUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.prepost.PreAuthorize;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class TestAIInsightsREST {
    private static final String TOKEN = "t0ken-t0ken-t0ken-t0ken-t0ken-t0ken-1234";
    private static final String URL   = "http://agent.internal.example:6090";

    private final Map<String, String> props = new HashMap<>();

    private final List<String> errorMessages = new ArrayList<>();

    private StubProxy proxy;
    private TestableREST rest;

    private String credentialResult;
    private int credentialCalls;
    private String proxyUrl;
    private String proxyToken;
    private int proxyCreated;

    /** Test double that reads settings from a map and returns a stub proxy. */
    private class TestableREST extends AIInsightsREST {
        @Override
        protected String property(String key) {
            return props.get(key);
        }

        @Override
        protected String decryptCredential(String providerPath, String alias, String storeType) {
            credentialCalls++;

            return credentialResult;
        }

        @Override
        protected AIInsightsProxy newProxy(String url, String token, int connectTimeoutMs, int readTimeoutMs) {
            proxyCreated++;
            proxyUrl   = url;
            proxyToken = token;

            // reuse the real validation so misconfiguration behaves as in production
            new AIInsightsProxy(url, token, connectTimeoutMs, readTimeoutMs);

            return proxy;
        }
    }

    /** Stands in for the real HTTP call; built with valid arguments so the base constructor passes. */
    private static class StubProxy extends AIInsightsProxy {
        String result = "{}";
        AIInsightsProxy.UpstreamException failure;

        StubProxy() {
            super("http://127.0.0.1:1", TOKEN, 1000, 1000);
        }

        @Override
        public String fetchInsightsJson() throws UpstreamException {
            if (failure != null) {
                throw failure;
            }

            return result;
        }
    }

    @BeforeEach
    public void setUp() {
        props.clear();

        credentialResult = null;
        credentialCalls  = 0;
        proxyCreated     = 0;
        proxyUrl         = null;
        proxyToken       = null;

        errorMessages.clear();

        proxy = new StubProxy();
        rest  = new TestableREST();

        rest.restErrorUtil = new RESTErrorUtil() {
            @Override
            public WebApplicationException createRESTException(int responseCode, String logMessage, boolean logError) {
                errorMessages.add(logMessage);

                return new WebApplicationException(Response.status(responseCode).build());
            }
        };

        props.put(AIInsightsREST.PROP_ENABLED, "true");
        props.put(AIInsightsREST.PROP_URL, URL);
        props.put(AIInsightsREST.PROP_TOKEN, TOKEN);
    }

    @Test
    public void testOnlySystemAdminsCanCallEveryEndpoint() {
        assertEquals("ai-insights", AIInsightsREST.class.getAnnotation(Path.class).value());

        int endpoints = 0;

        for (Method m : AIInsightsREST.class.getDeclaredMethods()) {
            if (m.isAnnotationPresent(Path.class) || m.isAnnotationPresent(GET.class)) {
                endpoints++;

                PreAuthorize guard = m.getAnnotation(PreAuthorize.class);

                assertNotNull(guard, m.getName() + " must be protected");
                assertEquals("hasRole('ROLE_SYS_ADMIN')", guard.value(), m.getName());
            }
        }

        assertTrue(endpoints >= 1);
    }

    @Test
    public void testExposesOnlyGetRequests() {
        for (Method m : AIInsightsREST.class.getDeclaredMethods()) {
            if (m.isAnnotationPresent(Path.class)) {
                assertTrue(m.isAnnotationPresent(GET.class), m.getName() + " must be GET only");
                assertFalse(m.isAnnotationPresent(javax.ws.rs.POST.class));
                assertFalse(m.isAnnotationPresent(javax.ws.rs.PUT.class));
                assertFalse(m.isAnnotationPresent(javax.ws.rs.DELETE.class));
            }
        }
    }

    @Test
    public void testDisabledByDefaultAndDoesNotContactTheAgent() {
        props.remove(AIInsightsREST.PROP_ENABLED);
        assertEquals(AIInsightsREST.DISABLED_JSON, rest.getReport());

        props.put(AIInsightsREST.PROP_ENABLED, "false");
        assertEquals(AIInsightsREST.DISABLED_JSON, rest.getReport());

        props.put(AIInsightsREST.PROP_ENABLED, "yes please");
        assertEquals(AIInsightsREST.DISABLED_JSON, rest.getReport());

        assertEquals(0, proxyCreated);
    }

    @Test
    public void testReturnsTheAgentReport() throws Exception {
        proxy.result = "{\"schema\":1}";

        assertEquals("{\"schema\":1}", rest.getReport());
        assertEquals(URL, proxyUrl);
        assertEquals(TOKEN, proxyToken);
    }

    @Test
    public void testTargetComesOnlyFromConfiguration() {
        // getReport takes no parameters, so a request cannot choose the target
        for (Method m : AIInsightsREST.class.getDeclaredMethods()) {
            if (m.isAnnotationPresent(Path.class)) {
                assertEquals(0, m.getParameterCount(), m.getName());
            }
        }
    }

    @Test
    public void testCredentialStoreTokenTakesPrecedence() throws Exception {
        proxy.result = "{}";

        props.put(AIInsightsREST.PROP_TOKEN_ALIAS, "ranger.ai.insights.token");
        props.put(AIInsightsREST.PROP_CREDENTIAL_PATH, "/etc/ranger/admin/rangeradmin.jceks");
        credentialResult = "from-keystore-from-keystore-from-keystore";

        rest.getReport();

        assertEquals(1, credentialCalls);
        assertEquals("from-keystore-from-keystore-from-keystore", proxyToken);
    }

    @Test
    public void testFallsBackToPlainTokenWhenAliasIsMissingFromStore() throws Exception {
        proxy.result = "{}";

        props.put(AIInsightsREST.PROP_TOKEN_ALIAS, "ranger.ai.insights.token");
        props.put(AIInsightsREST.PROP_CREDENTIAL_PATH, "/etc/ranger/admin/rangeradmin.jceks");

        for (String missing : new String[] {null, "", "  ", "none", "NONE"}) {
            credentialResult = missing;

            rest.getReport();

            assertEquals(TOKEN, proxyToken, "store result: " + missing);
        }
    }

    @Test
    public void testCredentialStoreIsNotReadWithoutAlias() throws Exception {
        proxy.result = "{}";

        props.put(AIInsightsREST.PROP_CREDENTIAL_PATH, "/etc/ranger/admin/rangeradmin.jceks");

        rest.getReport();

        assertEquals(0, credentialCalls);
    }

    @Test
    public void testMisconfigurationIsA503WithoutDetails() {
        String[][] bad = {
            {AIInsightsREST.PROP_URL, null},
            {AIInsightsREST.PROP_URL, "file:///etc/passwd"},
            {AIInsightsREST.PROP_URL, "http://user:" + TOKEN + "@agent:6090"},
            {AIInsightsREST.PROP_TOKEN, null},
            {AIInsightsREST.PROP_TOKEN, "has space"},
        };

        for (String[] change : bad) {
            setUp();

            if (change[1] == null) {
                props.remove(change[0]);
            } else {
                props.put(change[0], change[1]);
            }

            WebApplicationException e = assertThrows(WebApplicationException.class, () -> rest.getReport());

            assertEquals(503, e.getResponse().getStatus());

            assertEquals(1, errorMessages.size());

            String message = errorMessages.get(0);

            assertFalse(message.contains(TOKEN));
            assertFalse(message.contains("passwd"));
            assertFalse(message.contains("agent"));
        }
    }

    @Test
    public void testAgentFailureIsA502WithoutDetails() throws Exception {
        proxy.failure = new AIInsightsProxy.UpstreamException("AI insights service returned HTTP 500");

        WebApplicationException e = assertThrows(WebApplicationException.class, () -> rest.getReport());

        assertEquals(502, e.getResponse().getStatus());

        assertEquals(1, errorMessages.size());

        String message = errorMessages.get(0);

        assertFalse(message.contains("500"));
        assertFalse(message.contains(URL));
        assertFalse(message.contains(TOKEN));
    }

    @Test
    public void testInvalidTimeoutSettingFallsBackToDefaults() throws Exception {
        proxy.result = "{}";

        props.put(AIInsightsREST.PROP_CONNECT_TIMEOUT, "soon");
        props.put(AIInsightsREST.PROP_READ_TIMEOUT, "");

        assertEquals("{}", rest.getReport());
        assertTrue(errorMessages.isEmpty());
    }
}
