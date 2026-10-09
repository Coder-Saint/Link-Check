package com.urlverifier;

import com.urlverifier.check.ParsedUrl;
import com.urlverifier.net.SsrfGuard;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.URI;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SecurityTest {
    @Test
    void blocksPrivateAndMetadataAddresses() throws Exception {
        for (String ip : List.of("127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.1", "169.254.169.254",
                "0.0.0.0", "100.64.0.1", "::1", "fc00::1"))
            assertTrue(SsrfGuard.isBlocked(InetAddress.getByName(ip)), ip);
        assertFalse(SsrfGuard.isBlocked(InetAddress.getByName("8.8.8.8")));
    }

    @Test
    void rejectsOddPortsAndSchemes() {
        assertThrows(IllegalArgumentException.class, () -> SsrfGuard.checkUri(URI.create("http://example.com:8080/")));
        assertThrows(IllegalArgumentException.class, () -> SsrfGuard.checkUri(URI.create("ftp://example.com/")));
    }

    @Test
    void parsesCredentialTrickLikeABrowser() {
        ParsedUrl p = ParsedUrl.parse("http://paypal.com@evil.com/login");
        assertEquals("evil.com", p.asciiHost());
        assertEquals("paypal.com", p.userInfo());
    }
}
