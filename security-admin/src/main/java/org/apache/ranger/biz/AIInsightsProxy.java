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

package org.apache.ranger.biz;

import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import org.apache.http.HttpEntity;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * Fetches the AI Insights JSON from the ranger-ai-agent service.
 *
 * <p>This is a server-side proxy for a single, fixed endpoint. The target comes
 * from Ranger Admin configuration and is never derived from a request, so a
 * caller cannot use it to reach other hosts. Redirects are not followed.
 * Responses are size-limited and must be a JSON object.
 *
 * <p>Exception messages are written to the server log and must not contain the
 * token. Callers should not pass them to browsers.
 */
public class AIInsightsProxy {
    public static final String INSIGHTS_PATH          = "/api/v1/insights";
    public static final int    DEFAULT_MAX_RESPONSE_BYTES = 5 * 1024 * 1024;

    private final URI    endpoint;
    private final String token;
    private final int    connectTimeoutMs;
    private final int    readTimeoutMs;
    private final int    maxResponseBytes;

    public AIInsightsProxy(String baseUrl, String token, int connectTimeoutMs, int readTimeoutMs) {
        this(baseUrl, token, connectTimeoutMs, readTimeoutMs, DEFAULT_MAX_RESPONSE_BYTES);
    }

    AIInsightsProxy(String baseUrl, String token, int connectTimeoutMs, int readTimeoutMs, int maxResponseBytes) {
        if (connectTimeoutMs <= 0 || readTimeoutMs <= 0 || maxResponseBytes <= 0) {
            throw new IllegalArgumentException("timeouts and the response limit must be positive");
        }

        this.endpoint         = buildEndpoint(baseUrl);
        this.token            = validateToken(token);
        this.connectTimeoutMs = connectTimeoutMs;
        this.readTimeoutMs    = readTimeoutMs;
        this.maxResponseBytes = maxResponseBytes;
    }

    /**
     * Returns the agent's JSON body, unchanged, after checking that it is a JSON object.
     *
     * @throws UpstreamException if the agent is unreachable, answers with anything but 200,
     *                           redirects, sends too much data, or sends something that is not a JSON object
     */
    public String fetchInsightsJson() throws UpstreamException {
        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectTimeout(connectTimeoutMs)
                .setConnectionRequestTimeout(connectTimeoutMs)
                .setSocketTimeout(readTimeoutMs)
                .setRedirectsEnabled(false)
                .build();

        try (CloseableHttpClient client = HttpClients.custom()
                .setDefaultRequestConfig(requestConfig)
                .disableCookieManagement()
                .disableAutomaticRetries()
                .build()) {
            HttpGet get = new HttpGet(endpoint);

            get.setHeader("Authorization", "Bearer " + token);
            get.setHeader("Accept", "application/json");

            try (CloseableHttpResponse response = client.execute(get)) {
                int status = response.getStatusLine().getStatusCode();

                if (status != 200) {
                    throw new UpstreamException("AI insights service returned HTTP " + status);
                }

                HttpEntity entity = response.getEntity();

                if (entity == null) {
                    throw new UpstreamException("AI insights service returned no body");
                }

                if (entity.getContentLength() > maxResponseBytes) {
                    throw new UpstreamException("AI insights response is larger than " + maxResponseBytes + " bytes");
                }

                String body = readLimited(entity.getContent());

                requireJsonObject(body);

                return body;
            }
        } catch (IOException e) {
            throw new UpstreamException("request to AI insights service failed: " + e.getClass().getSimpleName(), e);
        }
    }

    private String readLimited(InputStream in) throws IOException, UpstreamException {
        ByteArrayOutputStream out   = new ByteArrayOutputStream();
        byte[]                buf   = new byte[8192];
        int                   total = 0;
        int                   n;

        while ((n = in.read(buf)) != -1) {
            total += n;

            if (total > maxResponseBytes) {
                throw new UpstreamException("AI insights response is larger than " + maxResponseBytes + " bytes");
            }

            out.write(buf, 0, n);
        }

        return new String(out.toByteArray(), StandardCharsets.UTF_8);
    }

    private static void requireJsonObject(String body) throws UpstreamException {
        JsonElement parsed;

        try {
            parsed = JsonParser.parseString(body);
        } catch (JsonParseException e) {
            throw new UpstreamException("AI insights service returned invalid JSON");
        }

        if (!parsed.isJsonObject()) {
            throw new UpstreamException("AI insights service returned JSON that is not an object");
        }
    }

    private static URI buildEndpoint(String baseUrl) {
        if (baseUrl == null || baseUrl.trim().isEmpty()) {
            throw new IllegalArgumentException("AI insights URL is not set");
        }

        URI base;

        try {
            base = new URI(baseUrl.trim());
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("AI insights URL is not a valid URI");
        }

        String scheme = base.getScheme() == null ? "" : base.getScheme().toLowerCase(Locale.ROOT);

        if (!"http".equals(scheme) && !"https".equals(scheme)) {
            throw new IllegalArgumentException("AI insights URL must use http or https");
        }

        if (base.getHost() == null) {
            throw new IllegalArgumentException("AI insights URL has no host");
        }

        if (base.getUserInfo() != null) {
            throw new IllegalArgumentException("AI insights URL must not contain credentials");
        }

        if (base.getRawQuery() != null || base.getRawFragment() != null) {
            throw new IllegalArgumentException("AI insights URL must not contain a query or fragment");
        }

        String path = base.getPath() == null ? "" : base.getPath();

        while (path.endsWith("/")) {
            path = path.substring(0, path.length() - 1);
        }

        try {
            return new URI(scheme, null, base.getHost(), base.getPort(), path + INSIGHTS_PATH, null, null);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("AI insights URL is not a valid URI");
        }
    }

    private static String validateToken(String token) {
        if (token == null || token.trim().isEmpty()) {
            throw new IllegalArgumentException("AI insights token is not set");
        }

        String trimmed = token.trim();

        for (int i = 0; i < trimmed.length(); i++) {
            char c = trimmed.charAt(i);

            // visible ASCII only: rules out spaces and line breaks that could split a header
            if (c < 0x21 || c > 0x7e) {
                throw new IllegalArgumentException("AI insights token contains invalid characters");
            }
        }

        return trimmed;
    }

    /** The agent could not be reached or did not return a usable response. */
    public static class UpstreamException extends Exception {
        private static final long serialVersionUID = 1L;

        public UpstreamException(String message) {
            super(message);
        }

        public UpstreamException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
