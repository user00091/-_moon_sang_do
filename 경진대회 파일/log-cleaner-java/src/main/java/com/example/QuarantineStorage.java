package com.example;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class QuarantineStorage {

    private final Path filePath;
    private final ObjectMapper objectMapper;

    // JSON 파일 저장용 내부 DTO (추가 의존성 없이 Instant를 ISO-8601 문자열로 안전하게 저장)
    private record StoredLogDto(
            String id,
            String reason,
            String raw,
            String status,
            String createdAt
    ) {
        static StoredLogDto from(QuarantineLog log) {
            return new StoredLogDto(
                    log.id(),
                    log.reason(),
                    log.raw(),
                    log.status(),
                    log.createdAt().toString()
            );
        }

        QuarantineLog toDomain() {
            return new QuarantineLog(
                    id,
                    reason,
                    raw,
                    status,
                    Instant.parse(createdAt)
            );
        }
    }

    public QuarantineStorage(Path filePath) {
        this.filePath = filePath;
        this.objectMapper = new ObjectMapper()
                .enable(SerializationFeature.INDENT_OUTPUT);
    }

    public Map<String, QuarantineLog> loadAll() throws IOException {
        Map<String, QuarantineLog> result = new LinkedHashMap<>();
        if (!Files.exists(filePath)) {
            return result;
        }
        String content = Files.readString(filePath).trim();
        if (content.isEmpty()) {
            return result;
        }

        List<StoredLogDto> items = objectMapper.readValue(content, new TypeReference<List<StoredLogDto>>() {});
        for (StoredLogDto dto : items) {
            QuarantineLog log = dto.toDomain();
            result.put(log.id(), log);
        }
        return result;
    }

    public void saveAll(Map<String, QuarantineLog> store) throws IOException {
        if (filePath.getParent() != null) {
            Files.createDirectories(filePath.getParent());
        }
        List<StoredLogDto> items = new ArrayList<>();
        for (QuarantineLog log : store.values()) {
            items.add(StoredLogDto.from(log));
        }
        String json = objectMapper.writeValueAsString(items);
        Files.writeString(filePath, json);
    }

    public Path getFilePath() {
        return filePath;
    }
}