package com.urlverifier.net;

import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.util.Timeout;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/** Fetches untrusted URLs: no auto-redirects, every hop re-validated, short timeouts, capped body size. */
@Component
public class SafeHttpClient {
    public static final int MAX_REDIRECTS = 8;
    private static final int MAX_BODY = 200_000;

    public record Hop(String url, int status, String location) {}

    public record Trace(List<Hop> hops, String body, String error) {
        public String finalUrl() { return hops.get(hops.size() - 1).url(); }
        public int finalStatus() { return hops.get(hops.size() - 1).status(); }
        public int redirects() { return (int) hops.stream().filter(h -> h.status() >= 300 && h.status() < 400).count(); }
    }

    private record Raw(int status, String location, String body) {}

    private final CloseableHttpClient client = HttpClients.custom()
            .setConnectionManager(PoolingHttpClientConnectionManagerBuilder.create()
                    .setDnsResolver(new SafeDnsResolver())
                    .setDefaultConnectionConfig(ConnectionConfig.custom()
                            .setConnectTimeout(Timeout.ofSeconds(4))
                            .setSocketTimeout(Timeout.ofSeconds(6)).build())
                    .build())
            .disableRedirectHandling()
            .disableAutomaticRetries()
            .setUserAgent("UrlVerifier/1.0 (+link safety checker)")
            .build();

    public Trace trace(String start) {
        List<Hop> hops = new ArrayList<>();
        URI cur = URI.create(start);
        for (int i = 0; i <= MAX_REDIRECTS; i++) {
            try {
                SsrfGuard.checkUri(cur);
                Raw r = fetch(cur);
                hops.add(new Hop(cur.toString(), r.status(), r.location()));
                boolean redirect = r.status() >= 300 && r.status() < 400 && r.location() != null;
                if (!redirect) return new Trace(hops, r.body(), null);
                if (i == MAX_REDIRECTS) return new Trace(hops, "", "The link redirects too many times.");
                cur = cur.resolve(r.location());
            } catch (Exception e) {
                hops.add(new Hop(cur.toString(), 0, null));
                return new Trace(hops, "", friendly(e));
            }
        }
        return new Trace(hops, "", "The link redirects too many times.");
    }

    private Raw fetch(URI uri) throws IOException {
        HttpGet get = new HttpGet(uri);
        get.setHeader("Accept", "text/html,application/rdap+json,application/json;q=0.9,*/*;q=0.5");
        return client.execute(get, resp -> {
            Header loc = resp.getFirstHeader("Location");
            int code = resp.getCode();
            String body = "";
            HttpEntity e = resp.getEntity();
            if (e != null && !(code >= 300 && code < 400)) {
                try (InputStream in = e.getContent()) {
                    body = new String(in.readNBytes(MAX_BODY), StandardCharsets.UTF_8);
                }
            }
            return new Raw(code, loc == null ? null : loc.getValue(), body);
        });
    }

    private static String friendly(Exception e) {
        if (e instanceof IllegalArgumentException) return e.getMessage();
        if (e instanceof UnknownHostException) return "The domain doesn't exist, or it points to a private network address.";
        if (e instanceof SocketTimeoutException || e instanceof org.apache.hc.client5.http.ConnectTimeoutException)
            return "The site took too long to respond.";
        if (e instanceof javax.net.ssl.SSLException) return "The site's HTTPS certificate couldn't be verified.";
        return "The site couldn't be reached.";
    }
}
