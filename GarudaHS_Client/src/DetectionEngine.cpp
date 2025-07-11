#include "../pch.h"
#include <Windows.h>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <regex>
#include <TlHelp32.h>
#include <Psapi.h>
#include "../include/DetectionEngine.h"

// Simple JSON parser for basic functionality
namespace SimpleJSON {
    std::string trim(const std::string& str) {
        size_t first = str.find_first_not_of(' ');
        if (first == std::string::npos) return "";
        size_t last = str.find_last_not_of(' ');
        return str.substr(first, (last - first + 1));
    }
    
    std::string extractStringValue(const std::string& line) {
        size_t start = line.find('"');
        if (start == std::string::npos) return "";
        start++;
        size_t end = line.find('"', start);
        if (end == std::string::npos) return "";
        return line.substr(start, end - start);
    }
    
    bool extractBoolValue(const std::string& line) {
        return line.find("true") != std::string::npos;
    }
    
    int extractIntValue(const std::string& line) {
        std::string trimmed = trim(line);
        size_t pos = trimmed.find_last_of(':');
        if (pos != std::string::npos) {
            std::string value = trim(trimmed.substr(pos + 1));
            value.erase(std::remove(value.begin(), value.end(), ','), value.end());
            return std::stoi(value);
        }
        return 0;
    }
}

namespace GarudaHS {

    DetectionEngine::DetectionEngine()
        : m_enableWhitelistProtection(true)
        , m_enablePathValidation(true)
        , m_enableFileHashValidation(false)
        , m_minimumActionLevel(ConfidenceLevel::HIGH)
        , m_totalScans(0)
        , m_detections(0)
        , m_falsePositives(0)
        , m_whitelistHits(0)
    {
    }

    DetectionEngine::~DetectionEngine() {
        // Destructor
    }

    bool DetectionEngine::Initialize() {
        LoadDefaultRules();
        LoadDefaultWhitelist();
        return true;
    }

    void DetectionEngine::LoadDefaultRules() {
        m_detectionRules.clear();
        
        // Critical threats - exact matches
        DetectionRule cheatEngine = {
            "CheatEngine_Exact",
            "cheatengine.exe",
            MatchType::EXACT_MATCH,
            ConfidenceLevel::CRITICAL,
            true,
            "Cheat Engine - Memory editor and debugger",
            false,
            {},
            0, 0
        };
        m_detectionRules.push_back(cheatEngine);
        
        DetectionRule openKore = {
            "OpenKore_Bot",
            "openkore.exe", 
            MatchType::EXACT_MATCH,
            ConfidenceLevel::CRITICAL,
            true,
            "OpenKore - Ragnarok Online bot",
            false,
            {},
            0, 0
        };
        m_detectionRules.push_back(openKore);
        
        // High confidence threats
        DetectionRule wpePro = {
            "WPE_PacketEditor",
            "wpepro.exe",
            MatchType::EXACT_MATCH,
            ConfidenceLevel::HIGH,
            true,
            "WPE Pro - Packet editor",
            false,
            {},
            0, 0
        };
        m_detectionRules.push_back(wpePro);
        
        DetectionRule rpe = {
            "RPE_PacketEditor",
            "rpe.exe",
            MatchType::EXACT_MATCH,
            ConfidenceLevel::HIGH,
            true,
            "RPE - Ragnarok Packet Editor",
            false,
            {"helper.exe", "wrapper.exe"},
            100000, 0
        };
        m_detectionRules.push_back(rpe);
        
        // Medium confidence - debuggers (could be legitimate)
        DetectionRule ollyDbg = {
            "Debuggers_OllyDbg",
            "ollydbg.exe",
            MatchType::EXACT_MATCH,
            ConfidenceLevel::MEDIUM,
            true,
            "OllyDbg - Assembly level debugger",
            false,
            {},
            0, 0
        };
        m_detectionRules.push_back(ollyDbg);
        
        DetectionRule x64dbg = {
            "Debuggers_x64dbg",
            "x64dbg.exe",
            MatchType::EXACT_MATCH,
            ConfidenceLevel::MEDIUM,
            true,
            "x64dbg - Advanced debugger",
            false,
            {},
            0, 0
        };
        m_detectionRules.push_back(x64dbg);
        
        // Low confidence - could be false positives
        DetectionRule ida = {
            "IDA_Disassembler",
            "ida",
            MatchType::STARTS_WITH,
            ConfidenceLevel::LOW,
            true,
            "IDA Pro - Disassembler (could be legitimate)",
            false,
            {"nvidia.exe", "aida64.exe"},
            5000000, 0
        };
        m_detectionRules.push_back(ida);
    }

    void DetectionEngine::LoadDefaultWhitelist() {
        m_globalWhitelist = {
            "explorer.exe", "winlogon.exe", "csrss.exe", "dwm.exe",
            "svchost.exe", "lsass.exe", "services.exe", "system",
            "smss.exe", "wininit.exe", "taskhost.exe", "taskhostw.exe",
            "nvidia.exe", "aida64.exe", "steam.exe", "discord.exe",
            "chrome.exe", "firefox.exe", "notepad.exe", "calc.exe"
        };
        
        m_trustedPaths = {
            "C:\\Windows\\System32\\",
            "C:\\Windows\\SysWOW64\\", 
            "C:\\Program Files\\",
            "C:\\Program Files (x86)\\",
            "C:\\Windows\\",
            "C:\\ProgramData\\Microsoft\\"
        };
    }

    bool DetectionEngine::IsWhitelisted(const std::string& processName) const {
        if (!m_enableWhitelistProtection) return false;
        
        std::string lowerName = processName;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
        
        return m_globalWhitelist.find(lowerName) != m_globalWhitelist.end();
    }

    bool DetectionEngine::IsInTrustedPath(const std::string& fullPath) const {
        if (!m_enablePathValidation || fullPath.empty()) return false;
        
        std::string lowerPath = fullPath;
        std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::tolower);
        
        for (const auto& trustedPath : m_trustedPaths) {
            std::string lowerTrusted = trustedPath;
            std::transform(lowerTrusted.begin(), lowerTrusted.end(), lowerTrusted.begin(), ::tolower);
            
            if (lowerPath.find(lowerTrusted) == 0) {
                return true;
            }
        }
        return false;
    }

    bool DetectionEngine::MatchesRule(const std::string& processName, const DetectionRule& rule) const {
        if (!rule.enabled) return false;
        
        std::string name = processName;
        std::string pattern = rule.pattern;
        
        if (!rule.caseSensitive) {
            std::transform(name.begin(), name.end(), name.begin(), ::tolower);
            std::transform(pattern.begin(), pattern.end(), pattern.begin(), ::tolower);
        }
        
        switch (rule.matchType) {
            case MatchType::EXACT_MATCH:
                return name == pattern;
                
            case MatchType::STARTS_WITH:
                return name.find(pattern) == 0;
                
            case MatchType::ENDS_WITH:
                return name.length() >= pattern.length() && 
                       name.substr(name.length() - pattern.length()) == pattern;
                       
            case MatchType::CONTAINS:
                return name.find(pattern) != std::string::npos;
                
            case MatchType::REGEX_MATCH:
                try {
                    std::regex regex(pattern, rule.caseSensitive ? std::regex_constants::ECMAScript : std::regex_constants::icase);
                    return std::regex_match(name, regex);
                } catch (const std::regex_error&) {
                    return false;
                }
                
            default:
                return false;
        }
    }

    bool DetectionEngine::CheckExceptions(const std::string& processName, const DetectionRule& rule) const {
        std::string lowerName = processName;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
        
        for (const auto& exception : rule.exceptions) {
            std::string lowerException = exception;
            std::transform(lowerException.begin(), lowerException.end(), lowerException.begin(), ::tolower);
            
            if (lowerName == lowerException) {
                return true; // Found in exceptions
            }
        }
        return false;
    }

    DetectionResult DetectionEngine::ScanProcess(const std::string& processName, DWORD processId) {
        DetectionResult result = {};
        result.processName = processName;
        result.isDetected = false;
        
        m_totalScans++;
        
        // Check whitelist first
        if (IsWhitelisted(processName)) {
            m_whitelistHits++;
            result.reason = "Process is whitelisted";
            return result;
        }
        
        // Check trusted path
        if (processId > 0) {
            std::string fullPath = GetProcessPath(processId);
            if (IsInTrustedPath(fullPath)) {
                result.reason = "Process is in trusted path: " + fullPath;
                return result;
            }
        }
        
        // Check against detection rules
        for (const auto& rule : m_detectionRules) {
            if (MatchesRule(processName, rule)) {
                // Check exceptions
                if (CheckExceptions(processName, rule)) {
                    result.reason = "Process matches exception list for rule: " + rule.name;
                    continue;
                }
                
                // File size validation
                if (processId > 0 && (rule.minFileSize > 0 || rule.maxFileSize > 0)) {
                    std::string fullPath = GetProcessPath(processId);
                    DWORD fileSize = GetFileSize(fullPath);
                    
                    if (rule.minFileSize > 0 && fileSize < rule.minFileSize) {
                        result.reason = "File size too small for rule: " + rule.name;
                        continue;
                    }
                    
                    if (rule.maxFileSize > 0 && fileSize > rule.maxFileSize) {
                        result.reason = "File size too large for rule: " + rule.name;
                        continue;
                    }
                }
                
                // Detection confirmed
                result.isDetected = true;
                result.ruleName = rule.name;
                result.matchType = rule.matchType;
                result.confidence = rule.confidence;
                result.reason = rule.description;
                
                m_detections++;
                break;
            }
        }
        
        return result;
    }

    std::string DetectionEngine::GetProcessPath(DWORD processId) const {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
        if (hProcess == nullptr) return "";
        
        char path[MAX_PATH];
        DWORD size = MAX_PATH;
        
        if (QueryFullProcessImageNameA(hProcess, 0, path, &size)) {
            CloseHandle(hProcess);
            return std::string(path);
        }
        
        CloseHandle(hProcess);
        return "";
    }

    DWORD DetectionEngine::GetFileSize(const std::string& filePath) const {
        if (filePath.empty()) return 0;
        
        HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, 
                                   nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) return 0;
        
        DWORD fileSize = ::GetFileSize(hFile, nullptr);
        CloseHandle(hFile);
        return fileSize;
    }

    // Getters
    DWORD DetectionEngine::GetTotalScans() const { return m_totalScans; }
    DWORD DetectionEngine::GetDetectionCount() const { return m_detections; }
    DWORD DetectionEngine::GetFalsePositiveCount() const { return m_falsePositives; }
    
    double DetectionEngine::GetAccuracyRate() const {
        if (m_totalScans == 0) return 0.0;
        return (double)(m_totalScans - m_falsePositives) / m_totalScans * 100.0;
    }

    void DetectionEngine::ResetStatistics() {
        m_totalScans = 0;
        m_detections = 0;
        m_falsePositives = 0;
        m_whitelistHits = 0;
    }

    bool DetectionEngine::AddDetectionRule(const DetectionRule& rule) {
        // Check if rule with same name exists
        for (const auto& existingRule : m_detectionRules) {
            if (existingRule.name == rule.name) {
                return false; // Rule already exists
            }
        }
        
        m_detectionRules.push_back(rule);
        return true;
    }

    std::vector<DetectionRule> DetectionEngine::GetDetectionRules() const {
        return m_detectionRules;
    }

    void DetectionEngine::SetMinimumActionLevel(ConfidenceLevel level) {
        m_minimumActionLevel = level;
    }

    void DetectionEngine::SetWhitelistProtection(bool enabled) {
        m_enableWhitelistProtection = enabled;
    }

    void DetectionEngine::SetPathValidation(bool enabled) {
        m_enablePathValidation = enabled;
    }

    bool DetectionEngine::LoadRulesFromFile(const std::string& rulesFile) {
        std::ifstream file(rulesFile);
        if (!file.is_open()) {
            return false;
        }

        m_detectionRules.clear();
        std::string line;
        DetectionRule currentRule = {};
        bool inRule = false;

        while (std::getline(file, line)) {
            line = SimpleJSON::trim(line);
            if (line.empty() || line[0] == '#') continue;

            if (line.find("\"name\":") != std::string::npos) {
                if (inRule) {
                    m_detectionRules.push_back(currentRule);
                }
                currentRule = {};
                inRule = true;
                currentRule.name = SimpleJSON::extractStringValue(line);
            }
            else if (line.find("\"pattern\":") != std::string::npos && inRule) {
                currentRule.pattern = SimpleJSON::extractStringValue(line);
            }
            else if (line.find("\"confidence\":") != std::string::npos && inRule) {
                int confidence = SimpleJSON::extractIntValue(line);
                currentRule.confidence = static_cast<ConfidenceLevel>(confidence);
            }
            else if (line.find("\"enabled\":") != std::string::npos && inRule) {
                currentRule.enabled = SimpleJSON::extractBoolValue(line);
            }
            else if (line.find("\"description\":") != std::string::npos && inRule) {
                currentRule.description = SimpleJSON::extractStringValue(line);
            }
        }

        if (inRule) {
            m_detectionRules.push_back(currentRule);
        }

        file.close();
        return true;
    }

    bool DetectionEngine::SaveRulesToFile(const std::string& rulesFile) const {
        std::ofstream file(rulesFile);
        if (!file.is_open()) {
            return false;
        }

        file << "{\n";
        file << "  \"detection_rules\": [\n";

        for (size_t i = 0; i < m_detectionRules.size(); ++i) {
            const auto& rule = m_detectionRules[i];
            file << "    {\n";
            file << "      \"name\": \"" << rule.name << "\",\n";
            file << "      \"pattern\": \"" << rule.pattern << "\",\n";
            file << "      \"match_type\": " << static_cast<int>(rule.matchType) << ",\n";
            file << "      \"confidence\": " << static_cast<int>(rule.confidence) << ",\n";
            file << "      \"enabled\": " << (rule.enabled ? "true" : "false") << ",\n";
            file << "      \"description\": \"" << rule.description << "\"\n";
            file << "    }";
            if (i < m_detectionRules.size() - 1) {
                file << ",";
            }
            file << "\n";
        }

        file << "  ]\n";
        file << "}\n";

        file.close();
        return true;
    }

    bool DetectionEngine::RemoveDetectionRule(const std::string& ruleName) {
        auto it = std::find_if(m_detectionRules.begin(), m_detectionRules.end(),
            [&ruleName](const DetectionRule& rule) {
                return rule.name == ruleName;
            });

        if (it != m_detectionRules.end()) {
            m_detectionRules.erase(it);
            return true;
        }
        return false;
    }

    bool DetectionEngine::AddToWhitelist(const std::string& processName) {
        if (processName.empty()) return false;
        m_globalWhitelist.insert(processName);
        return true;
    }

    bool DetectionEngine::RemoveFromWhitelist(const std::string& processName) {
        if (processName.empty()) return false;
        auto it = m_globalWhitelist.find(processName);
        if (it != m_globalWhitelist.end()) {
            m_globalWhitelist.erase(it);
            return true;
        }
        return false;
    }

    bool DetectionEngine::AddTrustedPath(const std::string& path) {
        if (path.empty()) return false;
        m_trustedPaths.insert(path);
        return true;
    }

    bool DetectionEngine::ValidateRules() const {
        for (const auto& rule : m_detectionRules) {
            if (rule.name.empty() || rule.pattern.empty()) {
                return false;
            }
            if (rule.confidence < ConfidenceLevel::LOW || rule.confidence > ConfidenceLevel::CRITICAL) {
                return false;
            }
        }
        return true;
    }

} // namespace GarudaHS
