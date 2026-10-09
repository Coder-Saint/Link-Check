package com.urlverifier.check;

import com.urlverifier.check.Finding.Severity;
import com.urlverifier.net.SafeHttpClient.Trace;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@Component
public class RedirectCheck implements UrlCheck {
    private static final String N = "Redirects";
    private static final Set<String> SHORTENERS = Set.of("bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly",
            "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at");

    @Override
    public List<Finding> run(Target t) {
        Trace tr = t.trace();
        List<Finding> out = new ArrayList<>();
        int redirects = tr.redirects();
        String finalHost = ParsedUrl.hostOf(tr.finalUrl());
        boolean otherSite = !finalHost.isEmpty() && !ParsedUrl.registered(finalHost).equals(t.url().registeredDomain());

        if (tr.error() != null) out.add(new Finding(N, 5, Severity.LOW, tr.error() + " We couldn't inspect the page itself."));
        if (redirects >= 3) out.add(new Finding(N, 10, Severity.MEDIUM, "It bounces through " + redirects + " redirects before landing."));
        if (redirects > 0 && otherSite) {
            if (SHORTENERS.contains(t.url().registeredDomain()))
                out.add(Finding.info(N, "This is a short link. The real destination is " + finalHost + "."));
            else
                out.add(new Finding(N, 10, Severity.MEDIUM, "It sends you to a different site (" + finalHost + ") than the one in the link."));
        }
        if (out.isEmpty()) out.add(Finding.ok(N, redirects == 0 ? "It goes straight to the page with no redirects." : "Redirects stay on the same site."));
        return out;
    }
}
