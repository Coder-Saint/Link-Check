# Link check (URL verifier)

Spring Boot 3 / Java 21 service that follows a link on the server side and explains whether it looks safe.

## Run
    mvn spring-boot:run        # then open http://localhost:8080
    mvn test                   # SSRF guard + URL parsing tests
    docker build -t url-verifier . && docker run -p 8080:8080 url-verifier

## How it works
`POST /api/analyze {"url": "..."}` -> `AnalysisService`:
1. `ParsedUrl` parses like a browser (text before the last `@` is credentials) and converts IDN to ASCII.
2. `SafeHttpClient` follows redirects manually (max 8). Every hop is re-validated by `SsrfGuard`
   (http/https, ports 80/443 only) and `SafeDnsResolver` rejects loopback/private/link-local/metadata IPs
   at connect time, which defeats DNS rebinding. Timeouts and a 200 KB body cap apply.
3. Every `UrlCheck` @Component runs in parallel on virtual threads; findings are summed into a 0-100 score.

Checks: StructureCheck, LookalikeCheck (Levenshtein + ICU confusables), RedirectCheck, DomainAgeCheck (RDAP), ContentCheck (Jsoup).
Add a check by implementing `UrlCheck` as a @Component. Results are cached 10 min; 10 requests/min/IP.

## Next steps
Google Safe Browsing / URLhaus lookups, TLS certificate inspection, persisted scan history (JPA),
sandboxed screenshots (Playwright in a locked-down container), benchmark vs PhishTank for resume numbers.
Behind a proxy, `server.forward-headers-strategy=native` makes the rate limiter see real client IPs.
