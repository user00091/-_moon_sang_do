package com.example.logmonitor;

import java.util.List;
import java.util.Map;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

@RestController
public class AnalysisController {

    private final RestClient flaskClient = RestClient.builder()
            .baseUrl("http://localhost:5000")
            .build();

    @PostMapping(
        path = "/api/run",
        consumes = MediaType.APPLICATION_JSON_VALUE,
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    public Map<?, ?> runAnalysis(@RequestBody Map<String, Object> request) {
        return flaskClient.post()
                .uri("/run")
                .contentType(MediaType.APPLICATION_JSON)
                .body(request)
                .retrieve()
                .body(Map.class);
    }
}
