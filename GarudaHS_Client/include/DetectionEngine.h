#pragma once

#ifndef DETECTIONENGINE_H
#define DETECTIONENGINE_H

#include <Windows.h>
#include <string>
#include <vector>
#include <unordered_set>
#include <regex>
#include <functional>

namespace GarudaHS {

    enum class MatchType {
        EXACT_MATCH = 0,        // Exact filename match
        STARTS_WITH = 1,        // Process name starts with pattern
        ENDS_WITH = 2,          // Process name ends with pattern
        CONTAINS = 3,           // Process name contains pattern (careful!)
        REGEX_MATCH = 4,        // Regex pattern matching
        HASH_MATCH = 5          // File hash matching (future)
    };

    enum class ConfidenceLevel {
        LOW = 1,                // 30% confidence - log only
        MEDIUM = 2,             // 70% confidence - warn user
        HIGH = 3,               // 90% confidence - auto-action
        CRITICAL = 4            // 99% confidence - immediate action
    };

    struct DetectionRule {
        std::string name;           // Rule name for logging
        std::string pattern;        // Pattern to match
        MatchType matchType;        // How to match
        ConfidenceLevel confidence; // Confidence level
        bool enabled;              // Rule enabled/disabled
        std::string description;    // Human readable description
        
        // Advanced options
        bool caseSensitive;        // Case sensitive matching
        std::vector<std::string> exceptions; // Whitelist exceptions
        DWORD minFileSize;         // Minimum file size (0 = ignore)
        DWORD maxFileSize;         // Maximum file size (0 = ignore)
    };

    struct DetectionResult {
        bool isDetected;
        std::string processName;
        std::string ruleName;
        MatchType matchType;
        ConfidenceLevel confidence;
        std::string reason;
        std::vector<std::string> additionalInfo;
    };

    /**
     * Advanced detection engine with configurable rules and false positive prevention
     */
    class DetectionEngine {
    private:
        std::vector<DetectionRule> m_detectionRules;
        std::unordered_set<std::string> m_globalWhitelist;
        std::unordered_set<std::string> m_trustedPaths;
        
        // Configuration
        bool m_enableWhitelistProtection;
        bool m_enablePathValidation;
        bool m_enableFileHashValidation;
        ConfidenceLevel m_minimumActionLevel;
        
        // Statistics
        DWORD m_totalScans;
        DWORD m_detections;
        DWORD m_falsePositives;
        DWORD m_whitelistHits;

        // Private methods
        bool IsWhitelisted(const std::string& processName) const;
        bool IsInTrustedPath(const std::string& fullPath) const;
        bool MatchesRule(const std::string& processName, const DetectionRule& rule) const;
        bool CheckExceptions(const std::string& processName, const DetectionRule& rule) const;
        std::string GetProcessPath(DWORD processId) const;
        DWORD GetFileSize(const std::string& filePath) const;

    public:
        DetectionEngine();
        ~DetectionEngine();
        
        // Lifecycle
        bool Initialize();
        bool LoadRulesFromFile(const std::string& rulesFile = "detection_rules.json");
        bool SaveRulesToFile(const std::string& rulesFile = "detection_rules.json") const;
        
        // Rule management
        bool AddDetectionRule(const DetectionRule& rule);
        bool RemoveDetectionRule(const std::string& ruleName);
        bool UpdateDetectionRule(const std::string& ruleName, const DetectionRule& newRule);
        std::vector<DetectionRule> GetDetectionRules() const;
        
        // Whitelist management
        bool AddToWhitelist(const std::string& processName);
        bool RemoveFromWhitelist(const std::string& processName);
        bool AddTrustedPath(const std::string& path);
        bool RemoveTrustedPath(const std::string& path);
        
        // Detection operations
        DetectionResult ScanProcess(const std::string& processName, DWORD processId = 0);
        std::vector<DetectionResult> ScanAllProcesses();
        
        // Configuration
        void SetMinimumActionLevel(ConfidenceLevel level);
        void SetWhitelistProtection(bool enabled);
        void SetPathValidation(bool enabled);
        
        // Statistics
        DWORD GetTotalScans() const;
        DWORD GetDetectionCount() const;
        DWORD GetFalsePositiveCount() const;
        double GetAccuracyRate() const;
        
        // Utility
        void ResetStatistics();
        std::vector<std::string> GetSuggestions() const;
        bool ValidateRules() const;
        
        // Default rules
        void LoadDefaultRules();
        void LoadDefaultWhitelist();
    };

} // namespace GarudaHS

#endif // DETECTIONENGINE_H
