package com.urlverifier.check;

import com.urlverifier.check.Finding.Severity;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@Component
public class StructureCheck implements UrlCheck {
    private static final String N = "Link structure";
    private static final Set<String> BAIT = Set.of("login", "signin", "verify", "secure", "account", "update", "wallet", "billing");

    @Override
    public List<Finding> run(Target t) {
        ParsedUrl u = t.url();
        List<Finding> out = new ArrayList<>();
        if (u.userInfo() != null)
            out.add(new Finding(N, 35, Severity.HIGH, "The link contains an '@'. Everything before it is only a username; the real destination is " + u.asciiHost() + "."));
        if (u.isIp())
            out.add(new Finding(N, 25, Severity.HIGH, "It uses a raw IP address instead of a domain name."));
        if (u.asciiHost().contains("xn--"))
            out.add(new Finding(N, 15, Severity.MEDIUM, "The domain uses international characters, which can imitate familiar letters."));
        int extra = u.asciiHost().split("\\.").length - u.registeredDomain().split("\\.").length;
        if (!u.isIp() && extra >= 3)
            out.add(new Finding(N, 10, Severity.MEDIUM, "It stacks " + extra + " subdomains in front of the real domain, a way to hide where it belongs."));
        if (u.scheme().equals("http"))
            out.add(new Finding(N, 10, Severity.LOW, "It isn't encrypted (http instead of https)."));
        String reg = u.registeredDomain();
        String tld = reg.substring(reg.lastIndexOf('.') + 1);
        if (Brands.RISKY_TLDS.contains(tld))
            out.add(new Finding(N, 10, Severity.LOW, "The ." + tld + " ending is heavily used by scam sites."));
        String label = reg.contains(".") ? reg.substring(0, reg.indexOf('.')) : reg;
        if (!u.isIp() && !Brands.isOfficial(reg) && BAIT.stream().anyMatch(label::contains))
            out.add(new Finding(N, 8, Severity.LOW, "Words like 'login' or 'secure' in the domain name are common in phishing."));
        if (u.original().length() > 120)
            out.add(new Finding(N, 5, Severity.LOW, "The link is unusually long."));
        if (out.isEmpty()) out.add(Finding.ok(N, "The link's structure looks ordinary."));
        return out;
    }
}
