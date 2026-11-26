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

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class TestAIInsightsProxy {
    private static final String TOKEN = "t0ken-t0ken-t0ken-t0ken-t0ken-t0ken-1234";

    private final AtomicReference<String> seenMethod = new AtomicReference<>();
    private final AtomicReference<String> seenPath   = new AtomicReference<>();
    private final AtomicReference<String> seenAuth   = new AtomicReference<>();
    private final AtomicReference<String> seenCookie = new AtomicReference<>();

    private HttpServer server;
    private HttpServer other;

    @AfterEach
    public void stopServers() {
        if (server != null) {
            server.stop(0);
        }

        if (other != null) {
            other.stop(0);
        }
    }

    @Test
    public void testReturnsBodyAndSendsBearerTokenOnFixedPath() throws Exception {
        start(reply(200, "{\"schema\":1}"));

        String body = new AIInsightsProxy(baseUrl(), TOKEN, 2000, 2000).fetchInsightsJson();

        assertEquals("{\"schema\":1}", body);
        assertEquals("GET", seenMethod.get());
        assertEquals("/api/v1/insights", seenPath.get());
        assertEquals("Bearer " + TOKEN, seenAuth.get());
        assertNull(seenCookie.get());
    }

    @Test
    public void testBaseUrlWithTrailingSlashAndPrefix() throws Exception {
        start(reply(200, "{}"));

        new AIInsightsProxy(baseUrl() + "/", TOKEN, 2000, 2000).fetchInsightsJson();
        assertEquals("/api/v1/insights", seenPath.get());

        new AIInsightsProxy(baseUrl() + "/agent/", TOKEN, 2000, 2000).fetchInsightsJson();
        assertEquals("/agent/api/v1/insights", seenPath.get());
    }

    @Test
    public void testNon200StatusIsAnError() throws Exception {
        for (int status : new int[] {401, 403, 404, 500, 503}) {
            start(reply(status, "{\"error\":\"x\"}"));

            AIInsightsProxy.UpstreamException e = assertThrows(AIInsightsProxy.UpstreamException.class,
                    () -> new AIInsightsProxy(baseUrl(), TOKEN, 2000, 2000).fetchInsightsJson());

            assertTrue(e.getMessage().contains(String.valueOf(status)), e.getMessage());

            server.stop(0);
        }
    }

    @Test
    public void testRedirectIsNotFollowed() throws Exception {
        AtomicInteger hitsOnOther = new AtomicInteger();

        other = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        other.createContext("/", exchange -> {
            hitsOnOther.incrementAndGet();
            respond(exchange, 200, "{\"leaked\":true}");
        });
        other.start();

        String target = "http://127.0.0.1:" + other.getAddress().getPort() + "/secret";

        start(exchange -> {
            exchange.getResponseHeaders().add("Location", target);
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });

        assertThrows(AIInsightsProxy.UpstreamException.class,
                () -> new AIInsightsProxy(baseUrl(), TOKEN, 2000, 2000).fetchInsightsJson());
        assertEquals(0, hitsOnOther.get());
    }

    @Test
    public void testBodyThatIsNotAJsonObjectIsRejected() throws Exception {
        for (String body : new String[] {"", "not json", "[1,2]", "\"text\"", "42", "null", "{\"a\":"}) {
            start(reply(200, body));

            assertThrows(AIInsightsProxy.UpstreamException.class,
                    () -> new AIInsightsProxy(baseUrl(), TOKEN, 2000, 2000).fetchInsightsJson(), "body: " + body);

            server.stop(0);
        }
    }

    @Test
    public void testOversizedBodyIsRejected() throws Exception {
        start(reply(200, "{\"pad\":\"" + new String(new char[500]).replace('\0', 'x') + "\"}"));

        AIInsightsProxy.UpstreamException e = assertThrows(AIInsightsProxy.UpstreamException.class,
                () -> new AIInsightsProxy(baseUrl(), TOKEN, 2000, 2000, 100).fetchInsightsJson());

        assertTrue(e.getMessage().contains("larger than"), e.getMessage());
    }

    @Test
    public void testSlowServerTimesOut() throws Exception {
        start(exchange -> {
            try {
                Thread.sleep(1500);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }

            respond(exchange, 200, "{}");
        });

        long started = System.nanoTime();

        assertThrows(AIInsightsProxy.UpstreamException.class,
                () -> new AIInsightsProxy(baseUrl(), TOKEN, 2000, 200).fetchInsightsJson());

        assertTrue((System.nanoTime() - started) / 1_000_000 < 1400, "should give up well before the server answers");
    }

    @Test
    public void testConnectionRefusedIsAnError() throws Exception {
        start(reply(200, "{}"));

        String url = baseUrl();

        server.stop(0);

        assertThrows(AIInsightsProxy.UpstreamException.class,
                () -> new AIInsightsProxy(url, TOKEN, 1000, 1000).fetchInsightsJson());
    }

    @Test
    public void testErrorMessagesNeverContainTheToken() throws Exception {
        start(reply(500, "{}"));

        AIInsightsProxy.UpstreamException e = assertThrows(AIInsightsProxy.UpstreamException.class,
                () -> new AIInsightsProxy(baseUrl(), TOKEN, 2000, 2000).fetchInsightsJson());

        assertFalse(e.getMessage().contains(TOKEN));
    }

    @Test
    public void testRejectsUnsafeUrls() {
        String[] bad = {
            null, "", "   ", "not a url", "file:///etc/passwd", "ftp://host/", "gopher://host:70/", "//host/path",
            "http://", "http://user:pass@host:6090", "http://host:6090?x=1", "http://host:6090#frag", "javascript:alert(1)"
        };

        for (String url : bad) {
            assertThrows(IllegalArgumentException.class, () -> new AIInsightsProxy(url, TOKEN, 1000, 1000), "url: " + url);
        }
    }

    @Test
    public void testAcceptsHttpAndHttps() {
        new AIInsightsProxy("http://127.0.0.1:6090", TOKEN, 1000, 1000);
        new AIInsightsProxy("https://agent.example.com:6090/", TOKEN, 1000, 1000);
        new AIInsightsProxy("HTTPS://agent.example.com", TOKEN, 1000, 1000);
    }

    @Test
    public void testRejectsBadTokens() {
        String[] bad = {null, "", "   ", "has space", "line\nbreak", "cr\rbreak", "tab\there", "caf\u00e9", "nu\u0000ll"};

        for (String token : bad) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> new AIInsightsProxy("http://127.0.0.1:6090", token, 1000, 1000), "token: " + token);

            if (token != null && !token.trim().isEmpty()) {
                assertFalse(e.getMessage().contains(token.trim()), "message must not echo the token");
            }
        }
    }

    @Test
    public void testRejectsNonPositiveLimits() {
        assertThrows(IllegalArgumentException.class, () -> new AIInsightsProxy("http://h", TOKEN, 0, 1000));
        assertThrows(IllegalArgumentException.class, () -> new AIInsightsProxy("http://h", TOKEN, 1000, -1));
        assertThrows(IllegalArgumentException.class, () -> new AIInsightsProxy("http://h", TOKEN, 1000, 1000, 0));
    }

    private HttpHandler reply(int status, String body) {
        return exchange -> respond(exchange, status, body);
    }

    private void respond(HttpExchange exchange, int status, String body) throws IOException {
        seenMethod.set(exchange.getRequestMethod());
        seenPath.set(exchange.getRequestURI().getPath());
        seenAuth.set(exchange.getRequestHeaders().getFirst("Authorization"));
        seenCookie.set(exchange.getRequestHeaders().getFirst("Cookie"));

        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);

        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);

        if (bytes.length > 0) {
            exchange.getResponseBody().write(bytes);
        }

        exchange.close();
    }

    private void start(HttpHandler handler) throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", handler);
        server.start();
    }

    private String baseUrl() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }
}
