package com.urlverifier.api;

import com.urlverifier.scoring.AnalysisResult;
import com.urlverifier.scoring.AnalysisService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api")
public class AnalyzeController {
    public record Request(String url) {}

    private final AnalysisService service;
    private final RateLimiter limiter = new RateLimiter(10, 60_000);

    public AnalyzeController(AnalysisService service) { this.service = service; }

    @PostMapping("/analyze")
    public AnalysisResult analyze(@RequestBody Request req, HttpServletRequest http) {
        if (!limiter.allow(http.getRemoteAddr()))
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "Too many checks. Wait a minute and try again.");
        try {
            return service.analyze(req == null ? null : req.url());
        } catch (IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
        }
    }
}
