package com.urlverifier.check;

import com.urlverifier.check.Finding.Severity;
import com.urlverifier.net.SafeHttpClient.Trace;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Reads the destination page as text only. Nothing is rendered or executed. */
@Component
public class ContentCheck implements UrlCheck {
    private static final String N = "Page content";

    @Override
    public List<Finding> run(Target t) {
        Trace tr = t.trace();
        if (tr.error() != null || tr.body() == null || tr.body().isBlank()) return List.of();
        Document d = Jsoup.parse(tr.body(), tr.finalUrl());
        String pageHost = ParsedUrl.hostOf(tr.finalUrl());
        String pageReg = ParsedUrl.registered(pageHost);
        List<Finding> out = new ArrayList<>();

        boolean password = !d.select("input[type=password]").isEmpty();
        if (password) out.add(new Finding(N, 10, Severity.LOW, "The page asks for a password. Only enter one if you're sure this is the real site."));

        for (Element form : d.select("form[action]")) {
            String host = ParsedUrl.hostOf(form.absUrl("action"));
            if (!host.isEmpty() && !ParsedUrl.registered(host).equals(pageReg)
                    && !form.select("input[type=password], input[type=email], input[type=text]").isEmpty()) {
                out.add(new Finding(N, 25, Severity.HIGH, "A form on this page sends what you type to " + host + ", a different site."));
                break;
            }
        }
        if (!d.select("iframe[style*=display:none], iframe[width=0], iframe[height=0], iframe[hidden]").isEmpty())
            out.add(new Finding(N, 15, Severity.MEDIUM, "The page contains a hidden frame, which can load content you can't see."));

        String title = d.title().toLowerCase(Locale.ROOT);
        if (password && !Brands.isOfficial(pageReg)) {
            for (Map.Entry<String, String> e : Brands.OFFICIAL.entrySet()) {
                if (title.contains(e.getKey())) {
                    out.add(new Finding(N, 25, Severity.HIGH, "The page presents itself as " + e.getKey() + " but isn't hosted on " + e.getValue() + "."));
                    break;
                }
            }
        }
        if (out.isEmpty()) out.add(Finding.ok(N, "No password prompts, hidden frames or suspicious forms found."));
        return out;
    }
}
