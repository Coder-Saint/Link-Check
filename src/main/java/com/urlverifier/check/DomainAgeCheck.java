package com.urlverifier.check;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.urlverifier.check.Finding.Severity;
import com.urlverifier.net.SafeHttpClient;
import com.urlverifier.net.SafeHttpClient.Trace;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.List;

/** Newly registered domains are a strong phishing signal. Uses RDAP, the modern WHOIS. */
@Component
public class DomainAgeCheck implements UrlCheck {
    private static final String N = "Domain age";
    private final SafeHttpClient http;
    private final ObjectMapper mapper = new ObjectMapper();

    public DomainAgeCheck(SafeHttpClient http) { this.http = http; }

    @Override
    public List<Finding> run(Target t) {
        if (t.url().isIp()) return List.of();
        Finding unknown = Finding.info(N, "We couldn't look up when this domain was registered.");
        try {
            Trace tr = http.trace("https://rdap.org/domain/" + t.url().registeredDomain());
            if (tr.error() != null || tr.finalStatus() != 200) return List.of(unknown);
            for (JsonNode ev : mapper.readTree(tr.body()).path("events")) {
                if ("registration".equals(ev.path("eventAction").asText())) {
                    Instant when = OffsetDateTime.parse(ev.path("eventDate").asText()).toInstant();
                    long days = Duration.between(when, Instant.now()).toDays();
                    if (days < 30) return List.of(new Finding(N, 35, Severity.HIGH, "This domain was registered only " + days + " days ago. Scam sites are often brand new."));
                    if (days < 180) return List.of(new Finding(N, 15, Severity.MEDIUM, "This domain is less than 6 months old (" + days + " days)."));
                    return List.of(Finding.ok(N, "The domain has existed for about " + Math.max(1, days / 365) + " year(s)."));
                }
            }
        } catch (Exception ignored) { /* fall through */ }
        return List.of(unknown);
    }
}
