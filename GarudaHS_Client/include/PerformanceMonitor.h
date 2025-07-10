#pragma once

#ifndef PERFORMANCEMONITOR_H
#define PERFORMANCEMONITOR_H

#include <Windows.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <chrono>
#include <mutex>

namespace GarudaHS {

    struct ProcessInfo {
        DWORD processId;
        std::string processName;
        DWORD lastSeen;
        bool isBlacklisted;
    };

    struct ScanStatistics {
        DWORD totalScans;
        DWORD averageScanTime;
        DWORD lastScanTime;
        DWORD processesScanned;
        DWORD blacklistedFound;
        DWORD cacheHits;
        DWORD cacheMisses;
    };

    /**
     * Performance optimization system with caching and smart intervals
     */
    class PerformanceMonitor {
    private:
        mutable std::mutex m_mutex;
        
        // Process cache
        std::unordered_map<DWORD, ProcessInfo> m_processCache;
        std::unordered_set<std::string> m_blacklistCache;
        
        // Performance tracking
        ScanStatistics m_stats;
        std::vector<DWORD> m_scanTimes;
        DWORD m_maxScanHistory;
        
        // Smart interval management
        DWORD m_baseScanInterval;
        DWORD m_currentScanInterval;
        DWORD m_minScanInterval;
        DWORD m_maxScanInterval;
        DWORD m_consecutiveCleanScans;
        DWORD m_adaptiveThreshold;
        
        // Cache management
        DWORD m_cacheTimeout;
        DWORD m_maxCacheSize;
        DWORD m_lastCacheCleanup;
        
        // Performance counters
        LARGE_INTEGER m_frequency;
        bool m_useHighResTimer;

    public:
        PerformanceMonitor();
        ~PerformanceMonitor();
        
        // Initialization
        bool Initialize();
        void Shutdown();
        
        // Cache management
        void UpdateProcessCache(const std::vector<ProcessInfo>& processes);
        bool IsProcessCached(DWORD processId) const;
        ProcessInfo GetCachedProcess(DWORD processId) const;
        void InvalidateProcessCache(DWORD processId);
        void ClearProcessCache();
        
        void UpdateBlacklistCache(const std::vector<std::string>& blacklist);
        bool IsBlacklistCached(const std::string& processName) const;
        void ClearBlacklistCache();
        
        // Performance tracking
        void StartScanTimer();
        void EndScanTimer();
        DWORD GetLastScanDuration() const;
        DWORD GetAverageScanDuration() const;
        
        // Smart interval management
        DWORD GetCurrentScanInterval() const;
        void UpdateScanInterval(bool cheatDetected);
        void SetBaseScanInterval(DWORD intervalMs);
        void SetAdaptiveThresholds(DWORD minInterval, DWORD maxInterval, DWORD threshold);
        
        // Statistics
        ScanStatistics GetStatistics() const;
        void ResetStatistics();
        void IncrementScanCount();
        void IncrementBlacklistedFound();
        void IncrementCacheHit();
        void IncrementCacheMiss();
        
        // Cache cleanup
        void CleanupExpiredCache();
        void OptimizeCache();
        
        // Configuration
        void SetCacheTimeout(DWORD timeoutMs);
        void SetMaxCacheSize(DWORD maxSize);
        void SetMaxScanHistory(DWORD maxHistory);
        
        // Utility
        double GetCacheHitRatio() const;
        DWORD GetCacheSize() const;
        bool ShouldCleanupCache() const;
        
        // Memory management
        size_t GetMemoryUsage() const;
        void OptimizeMemoryUsage();
        
        // Performance recommendations
        std::vector<std::string> GetPerformanceRecommendations() const;
        bool IsPerformanceOptimal() const;
    };

} // namespace GarudaHS

#endif // PERFORMANCEMONITOR_H
