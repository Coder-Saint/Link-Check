package com.urlverifier.net;

import java.net.InetAddress;
import java.net.URI;

/** Decides which destinations the server is allowed to contact. */
public final class SsrfGuard {
    private SsrfGuard() {}

    public static boolean isBlocked(InetAddress a) {
        if (a.isAnyLocalAddress() || a.isLoopbackAddress() || a.isLinkLocalAddress()   // includes 169.254.169.254
                || a.isSiteLocalAddress() || a.isMulticastAddress()) return true;
        byte[] b = a.getAddress();
        if (b.length == 4) {
            int f = b[0] & 0xff, s = b[1] & 0xff;
            if (f == 0 || f >= 240) return true;                       // "this" network, reserved
            if (f == 100 && s >= 64 && s <= 127) return true;          // carrier-grade NAT
            if (f == 192 && s == 0 && (b[2] & 0xff) == 0) return true; // IETF protocol assignments
        } else if (b.length == 16 && (b[0] & 0xfe) == 0xfc) {          // IPv6 unique local fc00::/7
            return true;
        }
        return false;
    }

    /** Throws IllegalArgumentException (with a user-safe message) if the URI must not be fetched. */
    public static void checkUri(URI u) {
        String scheme = u.getScheme();
        if (scheme == null || !(scheme.equals("http") || scheme.equals("https")))
            throw new IllegalArgumentException("Only http and https links can be checked.");
        if (u.getHost() == null || u.getHost().isBlank())
            throw new IllegalArgumentException("That link has no valid domain name.");
        int p = u.getPort();
        if (p != -1 && p != 80 && p != 443)
            throw new IllegalArgumentException("Links using unusual ports aren't fetched for safety.");
    }
}
