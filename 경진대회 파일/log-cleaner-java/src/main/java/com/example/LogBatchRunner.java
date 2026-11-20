package com.example;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.stream.Stream;

public class LogBatchRunner {

    private final QuarantineBridgeApp bridgeApp;
    private final Path incomingDir;
    private final Path processedDir;

    public LogBatchRunner(QuarantineBridgeApp bridgeApp, Path incomingDir, Path processedDir) throws IOException {
        this.bridgeApp = bridgeApp;
        this.incomingDir = incomingDir;
        this.processedDir = processedDir;
        Files.createDirectories(incomingDir);
        Files.createDirectories(processedDir);
    }

    public int scanAndProcessOnce(double th) throws IOException {
        int processedFiles = 0;

        try (Stream<Path> stream = Files.list(incomingDir)) {
            List<Path> files = stream
                    .filter(Files::isRegularFile)
                    .filter(p -> {
                        String name = p.getFileName().toString().toLowerCase();
                        return name.endsWith(".log") || name.endsWith(".jsonl") || name.endsWith(".txt");
                    })
                    .sorted()
                    .toList();

            for (Path file : files) {
                List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8).stream()
                        .map(String::trim)
                        .filter(line -> !line.isEmpty())
                        .toList();

                if (!lines.isEmpty()) {
                    try {
                        LogCleanerDtos.CleanResponse res = bridgeApp.processAndStore(false, lines, th);
                        System.out.printf("[배치 처리 완료] %s -> 전체: %d, 정상: %d, 격리: %d%n",
                                file.getFileName(), lines.size(), res.okCount(), res.quarantineCount());
                    } catch (Exception e) {
                        System.err.printf("[배치 처리 실패] %s -> %s%n", file.getFileName(), e.getMessage());
                        continue;
                    }
                }

                Path target = processedDir.resolve(file.getFileName());
                Files.move(file, target, StandardCopyOption.REPLACE_EXISTING);
                processedFiles++;
            }
        }

        return processedFiles;
    }

    public void startPolling(double th, long intervalMillis) {
        Thread worker = new Thread(() -> {
            System.out.println("로그 폴더 감시 시작: " + incomingDir.toAbsolutePath());
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    scanAndProcessOnce(th);
                    Thread.sleep(intervalMillis);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                } catch (Exception e) {
                    System.err.println("폴더 감시 중 오류: " + e.getMessage());
                }
            }
        }, "log-batch-watcher");
        worker.setDaemon(true);
        worker.start();
    }
}