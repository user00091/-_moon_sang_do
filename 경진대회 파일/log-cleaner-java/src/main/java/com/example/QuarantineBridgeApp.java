package com.example;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class QuarantineBridgeApp {

    private static final String BASE_URL = "http://127.0.0.1:5000";
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final QuarantineStorage storage;
    private final Map<String, QuarantineLog> quarantineStore;
    private final AlertReporter alertReporter;

    public QuarantineBridgeApp(Path storagePath, AlertReporter alertReporter) throws Exception {
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .build();
        this.objectMapper = new ObjectMapper();
        this.storage = new QuarantineStorage(storagePath);
        this.quarantineStore = new LinkedHashMap<>(storage.loadAll());
        this.alertReporter = alertReporter;
    }

    public synchronized LogCleanerDtos.CleanResponse processAndStore(boolean isSample, List<String> lines, double th) throws Exception {
        return processAndStore("api", isSample, lines, th);
    }

    public synchronized LogCleanerDtos.CleanResponse processAndStore(String source, boolean isSample, List<String> lines, double th) throws Exception {
        String requestBody = objectMapper.writeValueAsString(
                new LogCleanerDtos.CleanRequest(isSample, lines, th)
        );

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "/run"))
                .header("Content-Type", "application/json")
                .timeout(Duration.ofSeconds(30))
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new RuntimeException("Flask API 호출 실패 (" + response.statusCode() + "): " + response.body());
        }

        LogCleanerDtos.CleanResponse parsed = objectMapper.readValue(response.body(), LogCleanerDtos.CleanResponse.class);

        if (parsed.quarantine() != null && !parsed.quarantine().isEmpty()) {
            for (LogCleanerDtos.QuarantineItem item : parsed.quarantine()) {
                QuarantineLog saved = QuarantineLog.fromRejected(item.reason(), item.raw());
                quarantineStore.put(saved.id(), saved);
            }
            storage.saveAll(quarantineStore);
        }

        if (alertReporter != null) {
            alertReporter.evaluateAndRecord(source, parsed);
        }

        return parsed;
    }

    public synchronized LogCleanerDtos.CleanResponse reprocess(String quarantineId, String fixedRawLog, double th) throws Exception {
        QuarantineLog target = quarantineStore.get(quarantineId);
        if (target == null) {
            throw new IllegalArgumentException("격리 로그를 찾을 수 없습니다: " + quarantineId);
        }

        LogCleanerDtos.CleanResponse retryResponse = processAndStore("reprocess", false, List.of(fixedRawLog), th);
        if (retryResponse.okCount() > 0) {
            quarantineStore.put(quarantineId, target.markReprocessed());
            storage.saveAll(quarantineStore);
        }
        return retryResponse;
    }

    public synchronized Map<String, QuarantineLog> getAllLogs() {
        return Map.copyOf(quarantineStore);
    }

    public static void main(String[] args) throws Exception {
        Path storagePath = Path.of("data", "quarantine-logs.json");
        Path incomingDir = Path.of("data", "incoming-logs");
        Path processedDir = Path.of("data", "processed-logs");
        Path alertReportPath = Path.of("data", "alerts-report.log");

        AlertReporter reporter = new AlertReporter(alertReportPath, 1, 1);
        QuarantineBridgeApp bridge = new QuarantineBridgeApp(storagePath, reporter);

        if (bridge.getAllLogs().isEmpty()) {
            List<String> inputLogs = List.of(
                    "{\"ts\":\"2026-11-19T10:00:00\",\"level\":\"INFO\",\"service\":\"auth\",\"msg\":\"login ok\"}",
                    "{\"ts\":\"2026-11-19T10:01:00\",\"level\":\"INVALID\",\"service\":\"auth\",\"msg\":\"bad level\"}"
            );
            LogCleanerDtos.CleanResponse firstRun = bridge.processAndStore("init", false, inputLogs, 3.5);
            System.out.println("초기 실행 -> 정상: " + firstRun.okCount() + ", 격리: " + firstRun.quarantineCount());
        }

        LogBatchRunner batchRunner = new LogBatchRunner(bridge, incomingDir, processedDir);
        batchRunner.startPolling(3.5, 3000L);

        QuarantineHttpServer httpServer = new QuarantineHttpServer(8080, bridge);
        httpServer.start();
        System.out.println("저장 파일 위치: " + storagePath.toAbsolutePath());
        System.out.println("알림 리포트 위치: " + alertReportPath.toAbsolutePath());
    }
}