package com.urlverifier.check;

import com.ibm.icu.text.SpoofChecker;
import com.urlverifier.check.Finding.Severity;
import org.apache.commons.text.similarity.LevenshteinDistance;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

@Component
public class LookalikeCheck implements UrlCheck {
    private static final String N = "Lookalike domain";
    private final SpoofChecker spoof = new SpoofChecker.Builder().build();

    @Override
    public List<Finding> run(Target t) {
        ParsedUrl u = t.url();
        if (u.isIp()) return List.of();
        String reg = u.registeredDomain();
        if (Brands.isOfficial(reg)) return List.of(Finding.ok(N, "This is the official domain of a well-known service."));

        // 1) Non-ASCII labels visually confusable with a brand (homograph attack)
        for (String lbl : u.unicodeHost().split("\\.")) {
            if (lbl.chars().allMatch(c -> c < 128)) continue;
            for (String brand : Brands.OFFICIAL.keySet()) {
                try {
                    if (spoof.areConfusable(lbl, brand) != 0)
                        return List.of(new Finding(N, 45, Severity.HIGH, "The domain uses look-alike characters to imitate " + brand + "."));
                } catch (RuntimeException ignored) { /* skip */ }
            }
        }

        String label = reg.contains(".") ? reg.substring(0, reg.indexOf('.')) : reg;
        String tld = reg.substring(reg.lastIndexOf('.') + 1);
        String norm = normalize(label);
        for (Map.Entry<String, String> e : Brands.OFFICIAL.entrySet()) {
            String brand = e.getKey(), official = e.getValue();
            if (label.equals(brand)) {
                if (Brands.RISKY_TLDS.contains(tld))
                    return List.of(new Finding(N, 30, Severity.HIGH, "It borrows the name '" + brand + "' with a ." + tld + " ending. The real site is " + official + "."));
                continue;
            }
            if (u.asciiHost().contains(brand))
                return List.of(new Finding(N, 35, Severity.HIGH, "It mentions '" + brand + "', but the site actually belongs to " + reg + ", not " + official + "."));
            int d = LevenshteinDistance.getDefaultInstance().apply(norm, brand);
            if (d == 0 || (d == 1 && brand.length() >= 6))
                return List.of(new Finding(N, 40, Severity.HIGH, "'" + label + "' looks almost identical to " + brand + ". The real site is " + official + "."));
        }
        return List.of(Finding.ok(N, "It doesn't resemble any well-known brand."));
    }

    /** Undo common character swaps: paypa1 -> paypal, rnicrosoft -> microsoft. */
    static String normalize(String s) {
        return s.replace("-", "").replace("rn", "m").replace("vv", "w")
                .replace('0', 'o').replace('1', 'l').replace('5', 's').replace('3', 'e');
    }
}
