package com.flipkart.es.cache;

import java.time.Duration;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

@SuppressWarnings("null")
public class CacheStore<T> {

    private Cache<String, T> cache;

    public CacheStore(Duration expiryTime) {
        this.cache = CacheBuilder.newBuilder()
                .expireAfterWrite(expiryTime)
                .concurrencyLevel(Runtime.getRuntime().availableProcessors())
                .build();
    }

    public void add(String key, T value) {
        cache.put(key, value);
    }

    public T get(String key) {
        return cache.getIfPresent(key);
    }

    public void remove(String key) {
        cache.invalidate(key);
    }

}
