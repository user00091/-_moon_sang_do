package com.example;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;

public class AlertReporter {

    private final Path reportPath;
    private final int quarantineAlertThreshold;
    private final int anomalyAlertThreshold;

    public AlertReporter(Path reportPath, int quarantineAlertThreshold, int anomalyAlertThreshold) throws IOException {
        this.reportPath = reportPath;
        this.quarantineAlertThreshold = quarantineAlertThreshold;
        this.anomalyAlertThreshold = anomalyAlertThreshold;
        if (reportPath.getParent() != null) {
            Files.createDirectories(reportPath.getParent());
        }
    }

    public void evaluateAndRecord(String source, LogCleanerDtos.CleanResponse res) {
        if (res == null) {
            return;
        }
        boolean highQuarantine = res.quarantineCount() >= quarantineAlertThreshold;
        boolean highAnomaly = res.anomalies() >= anomalyAlertThreshold;

        if (!highQuarantine && !highAnomaly) {
            return;
        }

        String line = String.format(
                "[%s] [ALERT] source=%s | total=%d, ok=%d, quarantine=%d (기준 %d), anomalies=%d (기준 %d)%n",
                Instant.now(),
                source,
                res.total(),
                res.okCount(),
                res.quarantineCount(),
                quarantineAlertThreshold,
                res.anomalies(),
                anomalyAlertThreshold
        );

        System.err.print(line);
        try {
            Files.writeString(
                    reportPath,
                    line,
                    StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.APPEND
            );
        } catch (IOException e) {
            System.err.println("알림 리포트 기록 실패: " + e.getMessage());
        }
    }

    public Path getReportPath() {
        return reportPath;
    }
}