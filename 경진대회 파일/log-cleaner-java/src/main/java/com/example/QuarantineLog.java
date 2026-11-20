package com.example;

import java.time.Instant;
import java.util.UUID;

public record QuarantineLog(
        String id,
        String reason,
        String raw,
        String status,
        Instant createdAt
) {
    public static QuarantineLog fromRejected(String reason, String raw) {
        return new QuarantineLog(
                UUID.randomUUID().toString(),
                reason,
                raw,
                "QUARANTINED",
                Instant.now()
        );
    }

    public QuarantineLog markReprocessed() {
        return new QuarantineLog(id, reason, raw, "REPROCESSED", createdAt);
    }
}