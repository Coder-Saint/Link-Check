package com.urlverifier.check;

import java.util.Map;
import java.util.Set;

/** Brands that phishers imitate, with their official registered domains. Extend freely. */
public final class Brands {
    private Brands() {}

    public static final Map<String, String> OFFICIAL = Map.ofEntries(
            Map.entry("paypal", "paypal.com"), Map.entry("google", "google.com"),
            Map.entry("microsoft", "microsoft.com"), Map.entry("outlook", "outlook.com"),
            Map.entry("apple", "apple.com"), Map.entry("icloud", "icloud.com"),
            Map.entry("amazon", "amazon.com"), Map.entry("facebook", "facebook.com"),
            Map.entry("instagram", "instagram.com"), Map.entry("whatsapp", "whatsapp.com"),
            Map.entry("netflix", "netflix.com"), Map.entry("coinbase", "coinbase.com"),
            Map.entry("binance", "binance.com"), Map.entry("dropbox", "dropbox.com"),
            Map.entry("linkedin", "linkedin.com"), Map.entry("github", "github.com"),
            Map.entry("spotify", "spotify.com"), Map.entry("adobe", "adobe.com"),
            Map.entry("fedex", "fedex.com"), Map.entry("paytm", "paytm.com"),
            Map.entry("phonepe", "phonepe.com"), Map.entry("hdfcbank", "hdfcbank.com"),
            Map.entry("icicibank", "icicibank.com"), Map.entry("wellsfargo", "wellsfargo.com"));

    /** Legitimate domains that contain a brand name. */
    public static final Set<String> SAFE = Set.of("amazonaws.com", "googleapis.com", "googleusercontent.com",
            "microsoftonline.com", "githubusercontent.com", "github.io", "googlesyndication.com");

    public static final Set<String> RISKY_TLDS = Set.of("zip", "top", "xyz", "click", "country", "gq", "tk",
            "ml", "cf", "ga", "work", "support", "loan", "rest", "cam", "icu", "buzz");

    public static boolean isOfficial(String registered) {
        return OFFICIAL.containsValue(registered) || SAFE.contains(registered);
    }
}
