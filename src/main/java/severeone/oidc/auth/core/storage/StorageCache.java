package severeone.oidc.auth.core.storage;

// Fast short-living cache for Authorization Storage
public interface StorageCache {

    // set saves a key-value pair to cache
    void set(String key, Object value);

    // get search for a key in cache and returns it's corresponding value,
    // if it exists and is not expired. Returns null on a cache miss.
    Object get(String key);

    // remove deletes a key-value pair from cache, if a key exists
    void remove(String key);
}
