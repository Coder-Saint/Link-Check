package com.urlverifier.scoring;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.urlverifier.check.Finding;
import com.urlverifier.check.ParsedUrl;
import com.urlverifier.check.Target;
import com.urlverifier.check.UrlCheck;
import com.urlverifier.net.SafeHttpClient;
import com.urlverifier.net.SafeHttpClient.Trace;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

@Service
public class AnalysisService {
    private final SafeHttpClient http;
    private final List<UrlCheck> checks;
    private final ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor();
    private final Cache<String, AnalysisResult> cache =
            Caffeine.newBuilder().expireAfterWrite(Duration.ofMinutes(10)).maximumSize(1000).build();

    public AnalysisService(SafeHttpClient http, List<UrlCheck> checks) {
        this.http = http;
        this.checks = checks;
    }

    public AnalysisResult analyze(String raw) {
        ParsedUrl parsed = ParsedUrl.parse(raw);
        return cache.get(parsed.fetchUri().toString(), k -> run(parsed));
    }

    private AnalysisResult run(ParsedUrl p) {
        long t0 = System.nanoTime();
        Trace trace = http.trace(p.fetchUri().toString());
        Target target = new Target(p, trace);

        List<Future<List<Finding>>> futures = checks.stream().map(c -> pool.submit(() -> c.run(target))).toList();
        List<Finding> all = new ArrayList<>();
        for (Future<List<Finding>> f : futures) {
            try { all.addAll(f.get(15, TimeUnit.SECONDS)); } catch (Exception ignored) { /* one failing check never sinks the rest */ }
        }
        all.sort(Comparator.comparingInt(Finding::score).reversed());

        int score = Math.min(100, all.stream().mapToInt(Finding::score).sum());
        String verdict = score >= 55 ? "dangerous" : score >= 25 ? "suspicious" : "low-risk";
        String headline = switch (verdict) {
            case "dangerous" -> "Don't open this link";
            case "suspicious" -> "Be careful with this link";
            default -> "No red flags found";
        };
        return new AnalysisResult(p.original(), trace.finalUrl(), score, verdict, headline, all, trace.hops(),
                trace.error(), (System.nanoTime() - t0) / 1_000_000);
    }
}
