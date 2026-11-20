package com.example;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;

public class QuarantineHttpServer {

    private final HttpServer server;
    private final QuarantineBridgeApp bridgeApp;
    private final ObjectMapper objectMapper;

    public QuarantineHttpServer(int port, QuarantineBridgeApp bridgeApp) throws IOException {
        this.bridgeApp = bridgeApp;
        this.objectMapper = new ObjectMapper();
        this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);

        this.server.createContext("/api/quarantine", this::handleQuarantine);
        this.server.setExecutor(null);
    }

    public void start() {
        server.start();
        System.out.println("자바 격리 관리 API 서버 시작: http://127.0.0.1:" + server.getAddress().getPort() + "/api/quarantine");
    }

    private void handleQuarantine(HttpExchange exchange) throws IOException {
        addCorsHeaders(exchange);

        if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(204, -1);
            exchange.close();
            return;
        }

        String path = exchange.getRequestURI().getPath();
        String method = exchange.getRequestMethod();

        try {
            if ("/api/quarantine".equals(path) && "GET".equalsIgnoreCase(method)) {
                var items = new ArrayList<>();
                for (QuarantineLog log : bridgeApp.getAllLogs().values()) {
                    var map = new LinkedHashMap<String, Object>();
                    map.put("id", log.id());
                    map.put("reason", log.reason());
                    map.put("raw", log.raw());
                    map.put("status", log.status());
                    map.put("createdAt", log.createdAt().toString());
                    items.add(map);
                }
                sendJson(exchange, 200, Map.of("count", items.size(), "items", items));
                return;
            }

            if (path.startsWith("/api/quarantine/") && path.endsWith("/reprocess") && "POST".equalsIgnoreCase(method)) {
                String middle = path.substring("/api/quarantine/".length(), path.length() - "/reprocess".length());
                String id = URLDecoder.decode(middle, StandardCharsets.UTF_8);

                String body = readBody(exchange.getRequestBody());
                @SuppressWarnings("unchecked")
                Map<String, Object> reqMap = body.isBlank() ? Map.of() : objectMapper.readValue(body, Map.class);

                QuarantineLog existing = bridgeApp.getAllLogs().get(id);
                if (existing == null) {
                    sendJson(exchange, 404, Map.of("error", "격리 로그를 찾을 수 없습니다: " + id));
                    return;
                }

                String fixedRaw = reqMap.get("fixed_raw") instanceof String s && !s.isBlank()
                        ? s
                        : existing.raw();
                double th = reqMap.get("th") instanceof Number n ? n.doubleValue() : 3.5;

                LogCleanerDtos.CleanResponse res = bridgeApp.reprocess(id, fixedRaw, th);
                QuarantineLog updated = bridgeApp.getAllLogs().get(id);

                sendJson(exchange, 200, Map.of(
                        "id", id,
                        "ok_count", res.okCount(),
                        "quarantine_count", res.quarantineCount(),
                        "status", updated != null ? updated.status() : "UNKNOWN"
                ));
                return;
            }

            sendJson(exchange, 404, Map.of("error", "지원하지 않는 경로입니다."));
        } catch (Exception e) {
            sendJson(exchange, 500, Map.of("error", e.getMessage()));
        }
    }

    private void addCorsHeaders(HttpExchange exchange) {
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type");
    }

    private String readBody(InputStream is) throws IOException {
        try (is) {
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private void sendJson(HttpExchange exchange, int statusCode, Object payload) throws IOException {
        byte[] bytes = objectMapper.writeValueAsBytes(payload);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
}