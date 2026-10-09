package com.urlverifier.check;

import com.google.common.net.InternetDomainName;

import java.net.IDN;
import java.net.URI;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Parses the way a browser does: text before the last '@' is credentials, not the destination. */
public record ParsedUrl(String original, String scheme, String userInfo, String unicodeHost,
                        String asciiHost, URI fetchUri, String registeredDomain) {

    private static final Pattern SPLIT = Pattern.compile("(?i)^(https?)://([^/?#]*)([^#]*)");
    private static final Pattern IPV4 = Pattern.compile("\\d{1,3}(\\.\\d{1,3}){3}");

    public static ParsedUrl parse(String raw) {
        String s = raw == null ? "" : raw.trim();
        if (s.isEmpty()) throw new IllegalArgumentException("Paste a link to check.");
        if (s.length() > 2048) throw new IllegalArgumentException("That link is too long to check.");
        if (!s.matches("(?i)^[a-z][a-z0-9+.-]*://.*")) s = "https://" + s;
        Matcher m = SPLIT.matcher(s);
        if (!m.find()) throw new IllegalArgumentException("Only http and https links can be checked.");

        String scheme = m.group(1).toLowerCase(Locale.ROOT);
        String authority = m.group(2), rest = m.group(3), userInfo = null;
        int at = authority.lastIndexOf('@');
        if (at >= 0) { userInfo = authority.substring(0, at); authority = authority.substring(at + 1); }
        if (authority.startsWith("[")) throw new IllegalArgumentException("IPv6 addresses aren't supported.");
        String host = authority, port = "";
        int colon = authority.lastIndexOf(':');
        if (colon >= 0) { host = authority.substring(0, colon); port = authority.substring(colon); }
        if (host.isBlank()) throw new IllegalArgumentException("That link has no domain name.");

        String ascii;
        try {
            ascii = IDN.toASCII(host.toLowerCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("That domain name isn't valid.");
        }
        URI fetch;
        try {
            fetch = URI.create(scheme + "://" + ascii + port + rest);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("That link isn't formatted correctly.");
        }
        return new ParsedUrl(s, scheme, userInfo, IDN.toUnicode(ascii), ascii, fetch, registered(ascii));
    }

    public boolean isIp() { return IPV4.matcher(asciiHost).matches(); }

    public static String registered(String host) {
        try {
            return InternetDomainName.from(host).topPrivateDomain().toString();
        } catch (RuntimeException e) {
            String[] p = host.split("\\.");
            return p.length <= 2 ? host : p[p.length - 2] + "." + p[p.length - 1];
        }
    }

    public static String hostOf(String url) {
        try {
            String h = URI.create(url).getHost();
            return h == null ? "" : h.toLowerCase(Locale.ROOT);
        } catch (RuntimeException e) {
            return "";
        }
    }
}
