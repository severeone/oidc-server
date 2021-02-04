package severeone.oidc.auth.core.storage;

import org.apache.commons.collections4.map.LRUMap;

import java.time.Instant;

// Least Recently Used (LRU) cache
public class LRUStorageCache implements StorageCache {

	public interface TimeFunction { Instant now(); }

    private long entryDuration;
    private LRUMap<String, CacheEntry> cache;
    private TimeFunction time;

    private class CacheEntry {
        Instant lastSet;
        Object value;

        CacheEntry(Instant lastSet, Object value) {
            this.lastSet = lastSet;
            this.value = value;
        }
    }

    public LRUStorageCache(int cacheCapacity, int entryDurationSeconds) {
        this.entryDuration = entryDurationSeconds;
        this.cache = new LRUMap<>(cacheCapacity);
    }

    public LRUStorageCache(int cacheCapacity, int entryDurationSeconds, TimeFunction time) {
        this.entryDuration = entryDurationSeconds;
        this.cache = new LRUMap<>(cacheCapacity);
        this.time = time;
    }

    @Override
    public void set(String key, Object value) {
        cache.put(key, new CacheEntry(now(), value));
    }

    @Override
    public Object get(String key) {
        CacheEntry entry = cache.get(key);
        if (entry == null)
            return null;
        if (isExpired(entry)) {
            remove(key);
            return null;
        }
        return entry.value;
    }

    @Override
    public void remove(String key) {
        cache.remove(key);
    }

    private Instant now() {
    	if (time == null) {
            return Instant.now();
	    }
        return time.now();
    }

    private boolean isExpired(CacheEntry e) {
        return e.lastSet.plusSeconds(entryDuration).isBefore(now());
    }
}
