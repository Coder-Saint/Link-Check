package com.urlverifier.net;

import org.apache.hc.client5.http.DnsResolver;

import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * Resolves and validates in one step. The HTTP client connects to exactly the addresses
 * returned here, so a DNS-rebinding answer can't swap in an internal IP after validation.
 */
public class SafeDnsResolver implements DnsResolver {
    @Override
    public InetAddress[] resolve(String host) throws UnknownHostException {
        InetAddress[] all = InetAddress.getAllByName(host);
        for (InetAddress a : all) {
            if (SsrfGuard.isBlocked(a)) throw new UnknownHostException("Blocked address for " + host);
        }
        return all;
    }

    @Override
    public String resolveCanonicalHostname(String host) {
        return host;
    }
}
