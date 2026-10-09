package com.urlverifier.api;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Deque;

/** Sliding-window limiter, one window per client IP. */
public class RateLimiter {
    private final int max;
    private final long windowMs;
    private final Cache<String, Deque<Long>> windows = Caffeine.newBuilder()
            .expireAfterAccess(Duration.ofMinutes(5)).maximumSize(50_000).build();

    public RateLimiter(int max, long windowMs) { this.max = max; this.windowMs = windowMs; }

    public boolean allow(String key) {
        Deque<Long> q = windows.get(key, k -> new ArrayDeque<>());
        long now = System.currentTimeMillis();
        synchronized (q) {
            while (!q.isEmpty() && now - q.peekFirst() > windowMs) q.pollFirst();
            if (q.size() >= max) return false;
            q.addLast(now);
            return true;
        }
    }
}
