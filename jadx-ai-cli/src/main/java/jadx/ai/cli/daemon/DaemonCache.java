package jadx.ai.cli.daemon;

import java.util.LinkedHashMap;
import java.util.Map;

public class DaemonCache {

	private final long ttlMs;
	private final int maxSize;
	private final Map<String, CacheEntry> cache;
	private long hits;
	private long misses;

	public DaemonCache(long ttlMs, int maxSize) {
		this.ttlMs = ttlMs;
		this.maxSize = maxSize;
		this.cache = new LinkedHashMap<>(maxSize, 0.75f, true) {
			@Override
			protected boolean removeEldestEntry(Map.Entry<String, CacheEntry> eldest) {
				return size() > maxSize;
			}
		};
	}

	public synchronized Object get(String key) {
		CacheEntry entry = cache.get(key);
		if (entry == null || System.currentTimeMillis() - entry.timestamp > ttlMs) {
			if (entry != null) {
				cache.remove(key);
			}
			misses++;
			return null;
		}
		hits++;
		return entry.value;
	}

	public synchronized void put(String key, Object value) {
		cache.put(key, new CacheEntry(value, System.currentTimeMillis()));
	}

	public synchronized void invalidate(String key) {
		cache.remove(key);
	}

	public synchronized void invalidateAll() {
		cache.clear();
		hits = 0;
		misses = 0;
	}

	public synchronized int size() {
		return cache.size();
	}

	public synchronized CacheStats getStats() {
		CacheStats stats = new CacheStats();
		stats.size = cache.size();
		stats.maxSize = maxSize;
		stats.ttlMs = ttlMs;
		stats.hits = hits;
		stats.misses = misses;
		stats.hitRate = (hits + misses) > 0 ? (double) hits / (hits + misses) : 0.0;
		return stats;
	}

	public static class CacheEntry {
		final Object value;
		final long timestamp;

		CacheEntry(Object value, long timestamp) {
			this.value = value;
			this.timestamp = timestamp;
		}
	}

	public static class CacheStats {
		public int size;
		public int maxSize;
		public long ttlMs;
		public long hits;
		public long misses;
		public double hitRate;
	}
}
