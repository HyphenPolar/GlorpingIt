package aurick.opsec.mod.detection;

import aurick.opsec.mod.PrivacyLogger;
import aurick.opsec.mod.config.OpsecConstants;
import aurick.opsec.mod.util.LocalAddressUtil;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Detects fingerprinting attempts through resource pack requests.
 * Analyzes patterns such as rapid requests, hash probing, and suspicious URLs
 * to identify servers attempting to track or fingerprint clients.
 */
public class TrackPackDetector {

    private static final int[] KNOWN_DETECTION_PORTS = {
        15000, 25565, 8080, 3000, 4000, 5000, 8000, 9000, 1337, 7777
    };
    
    // Bounded collections to prevent memory leaks
    private static final Deque<RequestRecord> recentRequests = new ArrayDeque<>();
    private static final Set<String> uniqueHashes = new HashSet<>();
    private static final Object LOCK = new Object();
    
    private static final AtomicLong lastRequestTime = new AtomicLong(0);
    private static final AtomicInteger consecutiveRapidRequests = new AtomicInteger(0);
    private static final AtomicBoolean notifiedSuspiciousOnce = new AtomicBoolean(false);
    private static final AtomicBoolean notifiedPatternOnce = new AtomicBoolean(false);

    public record RequestRecord(String url, String hash, long timestamp) {}

    public static boolean recordRequest(String url, String hash) {
        long now = System.currentTimeMillis();
        boolean suspicious = isSuspiciousUrl(url);
        
        synchronized (LOCK) {
            // Remove expired entries and enforce size limit
            while (!recentRequests.isEmpty() && 
                   (now - recentRequests.peekFirst().timestamp > OpsecConstants.Detection.DETECTION_WINDOW_MS ||
                    recentRequests.size() >= OpsecConstants.Limits.MAX_RECENT_REQUESTS)) {
                recentRequests.pollFirst();
            }
            
            // Clear hashes if no recent requests
            if (recentRequests.isEmpty()) {
                uniqueHashes.clear();
            }
            
            // Track hash with size limit
            if (hash != null && !hash.isEmpty()) {
                if (uniqueHashes.size() >= OpsecConstants.Limits.MAX_UNIQUE_HASHES) {
                    uniqueHashes.clear();
                }
                uniqueHashes.add(hash);
            }
            
            recentRequests.addLast(new RequestRecord(url, hash, now));
        }
        
        long lastTime = lastRequestTime.get();
        if (lastTime > 0 && (now - lastTime) < OpsecConstants.Detection.RAPID_REQUEST_INTERVAL_MS) {
            consecutiveRapidRequests.incrementAndGet();
        } else {
            consecutiveRapidRequests.set(0);
        }
        lastRequestTime.set(now);
        
        analyzePatterns(url);
        return suspicious;
    }
    
    private static void analyzePatterns(String url) {
        if (isRapidRequestPattern()) {
            int rapidCount = consecutiveRapidRequests.get();
            PrivacyLogger.logDetection("TrackPack", "Rapid request pattern: " + rapidCount);
        }

        if (isHashProbing()) {
            int hashCount;
            synchronized (LOCK) {
                hashCount = uniqueHashes.size();
            }
            PrivacyLogger.logDetection("TrackPack", "Hash probing: " + hashCount + " hashes");
        }
    }
    
    private static boolean isSuspiciousUrl(String url) {
        if (url == null || url.isEmpty()) return false;

        if (isLocalUrl(url)) {
            return true;
        }

        if (isClientDetectionPort(url)) {
            return true;
        }

        if (url.contains(":0/") || url.endsWith(":0")) {
            return true;
        }

        return false;
    }

    private static boolean isClientDetectionPort(String url) {
        try {
            URI uri = new URI(url);
            String host = uri.getHost();
            int port = uri.getPort();
            
            if (port == -1 || host == null) return false;
            
            if (isLocalUrl(url)) {
                for (int p : KNOWN_DETECTION_PORTS) {
                    if (port == p) return true;
                }
            }
        } catch (java.net.URISyntaxException e) {
            aurick.opsec.mod.Opsec.LOGGER.debug("[TrackPackDetector] Failed to parse detection port from URL: {}", e.getMessage());
        }
        
        return false;
    }
    
    private static boolean isRapidRequestPattern() {
        if (consecutiveRapidRequests.get() >= OpsecConstants.Detection.RAPID_REQUEST_THRESHOLD) {
            return true;
        }
        
        long now = System.currentTimeMillis();
        synchronized (LOCK) {
            long rapidCount = recentRequests.stream()
                .filter(r -> now - r.timestamp < OpsecConstants.Detection.RAPID_WINDOW_MS)
                .count();
            return rapidCount >= OpsecConstants.Detection.RAPID_REQUEST_THRESHOLD;
        }
    }
    
    private static boolean isHashProbing() {
        synchronized (LOCK) {
            if (recentRequests.size() < OpsecConstants.Detection.MIN_REQUESTS_FOR_HASH_ANALYSIS) {
                return false;
            }
        double uniqueRatio = (double) uniqueHashes.size() / recentRequests.size();
        return uniqueHashes.size() >= OpsecConstants.Detection.UNIQUE_HASH_THRESHOLD 
            && uniqueRatio > OpsecConstants.Detection.HASH_PROBING_RATIO_THRESHOLD;
        }
    }
    
    public static boolean isFingerprinting() {
        long now = System.currentTimeMillis();
        synchronized (LOCK) {
            long count = recentRequests.stream()
                .filter(r -> now - r.timestamp < OpsecConstants.Detection.DETECTION_WINDOW_MS)
                .count();
        return count >= OpsecConstants.Detection.FINGERPRINT_THRESHOLD;
        }
    }

    public static boolean consumeNotifySuspiciousOnce() {
        return notifiedSuspiciousOnce.compareAndSet(false, true);
    }

    public static boolean consumeNotifyPatternOnce() {
        return notifiedPatternOnce.compareAndSet(false, true);
    }
    
    /**
     * Checks if a URL points to a local/private address by extracting the host
     * and delegating to {@link LocalAddressUtil#isLocalAddress(String)}.
     */
    private static boolean isLocalUrl(String url) {
        try {
            URI uri = new URI(url);
            String host = uri.getHost();
            if (host == null) return false;
            return LocalAddressUtil.isLocalAddress(host);
        } catch (URISyntaxException | UnknownHostException e) {
            return false;
        }
    }

    public static void reset() {
        synchronized (LOCK) {
        recentRequests.clear();
            uniqueHashes.clear();
        }
        consecutiveRapidRequests.set(0);
        lastRequestTime.set(0);
        notifiedSuspiciousOnce.set(false);
        notifiedPatternOnce.set(false);
    }
}
