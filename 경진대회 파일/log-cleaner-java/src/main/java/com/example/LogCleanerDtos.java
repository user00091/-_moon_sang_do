package com.example;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public class LogCleanerDtos {

    public record CleanRequest(
            @JsonProperty("is_sample") boolean isSample,
            List<String> lines,
            double th
    ) {}

    public record QuarantineItem(
            String reason,
            String raw
    ) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record CleanResponse(
            int total,
            @JsonProperty("ok_count") int okCount,
            @JsonProperty("quarantine_count") int quarantineCount,
            List<QuarantineItem> quarantine,
            @JsonProperty("masked_count") int maskedCount,
            int anomalies
    ) {}
}