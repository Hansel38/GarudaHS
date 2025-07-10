#include <Windows.h>
#undef min
#undef max
#include <algorithm>
#include <numeric>
#include "../include/PerformanceMonitor.h"

namespace GarudaHS {

    PerformanceMonitor::PerformanceMonitor()
        : m_maxScanHistory(100)
        , m_baseScanInterval(3000)
        , m_currentScanInterval(3000)
        , m_minScanInterval(1000)
        , m_maxScanInterval(10000)
        , m_consecutiveCleanScans(0)
        , m_adaptiveThreshold(5)
        , m_cacheTimeout(30000) // 30 seconds
        , m_maxCacheSize(1000)
        , m_lastCacheCleanup(0)
        , m_useHighResTimer(false)
    {
        ZeroMemory(&m_stats, sizeof(ScanStatistics));
        ZeroMemory(&m_frequency, sizeof(LARGE_INTEGER));
    }

    PerformanceMonitor::~PerformanceMonitor() {
        Shutdown();
    }

    bool PerformanceMonitor::Initialize() {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        // Initialize high-resolution timer if available
        m_useHighResTimer = QueryPerformanceFrequency(&m_frequency) != FALSE;
        
        m_scanTimes.reserve(m_maxScanHistory);
        m_lastCacheCleanup = GetTickCount();
        
        return true;
    }

    void PerformanceMonitor::Shutdown() {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        ClearProcessCache();
        ClearBlacklistCache();
        m_scanTimes.clear();
    }

    void PerformanceMonitor::UpdateProcessCache(const std::vector<ProcessInfo>& processes) {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        DWORD currentTime = GetTickCount();
        
        for (const auto& process : processes) {
            m_processCache[process.processId] = process;
        }
        
        // Cleanup if cache is getting too large
        if (m_processCache.size() > m_maxCacheSize) {
            OptimizeCache();
        }
    }

    bool PerformanceMonitor::IsProcessCached(DWORD processId) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        auto it = m_processCache.find(processId);
        if (it == m_processCache.end()) {
            return false;
        }
        
        // Check if cache entry is still valid
        DWORD currentTime = GetTickCount();
        return (currentTime - it->second.lastSeen) < m_cacheTimeout;
    }

    ProcessInfo PerformanceMonitor::GetCachedProcess(DWORD processId) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        auto it = m_processCache.find(processId);
        if (it != m_processCache.end()) {
            return it->second;
        }
        
        ProcessInfo empty = {};
        return empty;
    }

    void PerformanceMonitor::InvalidateProcessCache(DWORD processId) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_processCache.erase(processId);
    }

    void PerformanceMonitor::ClearProcessCache() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_processCache.clear();
    }

    void PerformanceMonitor::UpdateBlacklistCache(const std::vector<std::string>& blacklist) {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        m_blacklistCache.clear();
        for (const auto& item : blacklist) {
            m_blacklistCache.insert(item);
        }
    }

    bool PerformanceMonitor::IsBlacklistCached(const std::string& processName) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_blacklistCache.find(processName) != m_blacklistCache.end();
    }

    void PerformanceMonitor::ClearBlacklistCache() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_blacklistCache.clear();
    }

    void PerformanceMonitor::StartScanTimer() {
        // Timer start is handled in EndScanTimer for simplicity
    }

    void PerformanceMonitor::EndScanTimer() {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        static DWORD scanStartTime = GetTickCount();
        DWORD scanEndTime = GetTickCount();
        DWORD scanDuration = scanEndTime - scanStartTime;
        
        m_scanTimes.push_back(scanDuration);
        
        // Keep only recent scan times
        if (m_scanTimes.size() > m_maxScanHistory) {
            m_scanTimes.erase(m_scanTimes.begin());
        }
        
        // Update statistics
        if (!m_scanTimes.empty()) {
            m_stats.averageScanTime = static_cast<DWORD>(
                std::accumulate(m_scanTimes.begin(), m_scanTimes.end(), 0ULL) / m_scanTimes.size()
            );
        }
        m_stats.lastScanTime = scanDuration;
        
        scanStartTime = GetTickCount(); // Reset for next scan
    }

    DWORD PerformanceMonitor::GetLastScanDuration() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_stats.lastScanTime;
    }

    DWORD PerformanceMonitor::GetAverageScanDuration() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_stats.averageScanTime;
    }

    DWORD PerformanceMonitor::GetCurrentScanInterval() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_currentScanInterval;
    }

    void PerformanceMonitor::UpdateScanInterval(bool cheatDetected) {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        if (cheatDetected) {
            // Reset to base interval when cheat is detected
            m_currentScanInterval = m_baseScanInterval;
            m_consecutiveCleanScans = 0;
        } else {
            m_consecutiveCleanScans++;
            
            // Gradually increase interval if no cheats found
            if (m_consecutiveCleanScans >= m_adaptiveThreshold) {
                m_currentScanInterval = std::min(
                    m_currentScanInterval + 500, // Increase by 500ms
                    m_maxScanInterval
                );
            }
        }
        
        // Ensure interval stays within bounds
        m_currentScanInterval = std::max(m_currentScanInterval, m_minScanInterval);
        m_currentScanInterval = std::min(m_currentScanInterval, m_maxScanInterval);
    }

    void PerformanceMonitor::SetBaseScanInterval(DWORD intervalMs) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_baseScanInterval = intervalMs;
        m_currentScanInterval = intervalMs;
    }

    void PerformanceMonitor::SetAdaptiveThresholds(DWORD minInterval, DWORD maxInterval, DWORD threshold) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_minScanInterval = minInterval;
        m_maxScanInterval = maxInterval;
        m_adaptiveThreshold = threshold;
    }

    ScanStatistics PerformanceMonitor::GetStatistics() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_stats;
    }

    void PerformanceMonitor::ResetStatistics() {
        std::lock_guard<std::mutex> lock(m_mutex);
        ZeroMemory(&m_stats, sizeof(ScanStatistics));
        m_scanTimes.clear();
    }

    void PerformanceMonitor::IncrementScanCount() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_stats.totalScans++;
    }

    void PerformanceMonitor::IncrementBlacklistedFound() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_stats.blacklistedFound++;
    }

    void PerformanceMonitor::IncrementCacheHit() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_stats.cacheHits++;
    }

    void PerformanceMonitor::IncrementCacheMiss() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_stats.cacheMisses++;
    }

    void PerformanceMonitor::CleanupExpiredCache() {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        DWORD currentTime = GetTickCount();
        
        auto it = m_processCache.begin();
        while (it != m_processCache.end()) {
            if ((currentTime - it->second.lastSeen) > m_cacheTimeout) {
                it = m_processCache.erase(it);
            } else {
                ++it;
            }
        }
        
        m_lastCacheCleanup = currentTime;
    }

    void PerformanceMonitor::OptimizeCache() {
        if (m_processCache.size() <= m_maxCacheSize) {
            return;
        }
        
        // Remove oldest entries
        std::vector<std::pair<DWORD, DWORD>> entries; // processId, lastSeen
        for (const auto& pair : m_processCache) {
            entries.push_back({pair.first, pair.second.lastSeen});
        }
        
        // Sort by lastSeen (oldest first)
        std::sort(entries.begin(), entries.end(), 
                  [](const auto& a, const auto& b) { return a.second < b.second; });
        
        // Remove oldest entries until we're under the limit
        size_t toRemove = m_processCache.size() - (m_maxCacheSize * 3 / 4); // Remove 25% extra
        for (size_t i = 0; i < toRemove && i < entries.size(); ++i) {
            m_processCache.erase(entries[i].first);
        }
    }

    double PerformanceMonitor::GetCacheHitRatio() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        DWORD totalAccesses = m_stats.cacheHits + m_stats.cacheMisses;
        if (totalAccesses == 0) {
            return 0.0;
        }
        
        return static_cast<double>(m_stats.cacheHits) / totalAccesses;
    }

    DWORD PerformanceMonitor::GetCacheSize() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return static_cast<DWORD>(m_processCache.size());
    }

    bool PerformanceMonitor::ShouldCleanupCache() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        DWORD currentTime = GetTickCount();
        return (currentTime - m_lastCacheCleanup) > (m_cacheTimeout / 2);
    }

    size_t PerformanceMonitor::GetMemoryUsage() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        size_t usage = 0;
        usage += m_processCache.size() * sizeof(ProcessInfo);
        usage += m_blacklistCache.size() * 20; // Estimate for string storage
        usage += m_scanTimes.size() * sizeof(DWORD);
        
        return usage;
    }

    void PerformanceMonitor::OptimizeMemoryUsage() {
        CleanupExpiredCache();
        OptimizeCache();
        
        // Shrink scan times vector if it's too large
        if (m_scanTimes.capacity() > m_maxScanHistory * 2) {
            std::vector<DWORD> temp(m_scanTimes);
            m_scanTimes = std::move(temp);
        }
    }

    std::vector<std::string> PerformanceMonitor::GetPerformanceRecommendations() const {
        std::vector<std::string> recommendations;
        
        if (GetCacheHitRatio() < 0.7) {
            recommendations.push_back("Consider increasing cache timeout for better performance");
        }
        
        if (GetAverageScanDuration() > 100) {
            recommendations.push_back("Scan duration is high, consider optimizing blacklist");
        }
        
        if (GetCacheSize() > m_maxCacheSize * 0.9) {
            recommendations.push_back("Cache is nearly full, consider increasing max cache size");
        }
        
        return recommendations;
    }

    bool PerformanceMonitor::IsPerformanceOptimal() const {
        return GetCacheHitRatio() > 0.8 && 
               GetAverageScanDuration() < 50 && 
               GetCacheSize() < m_maxCacheSize * 0.8;
    }

} // namespace GarudaHS
