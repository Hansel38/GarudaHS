#pragma once

#ifndef FILEINTEGRITYVALIDATOR_H
#define FILEINTEGRITYVALIDATOR_H

#include <windows.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <atomic>
#include <functional>
#include <chrono>

namespace GarudaHS {

    // Hash algorithm types (matching client)
    enum class HashAlgorithm {
        MD5 = 1,
        CRC32 = 2,
        SHA1 = 3,
        SHA256 = 4,
        SHA512 = 5
    };

    // Validation request from client
    struct ValidationRequest {
        std::string clientId;
        std::string sessionToken;
        std::string filePath;
        std::string fileHash;
        HashAlgorithm algorithm;
        DWORD fileSize;
        std::string timestamp;
        std::string signature; // For anti-spoofing
    };

    // Validation response to client
    struct ValidationResponse {
        bool isValid;
        bool isAuthorized;
        std::string reason;
        float confidence;
        std::string serverTimestamp;
        std::string responseSignature;
        std::vector<std::string> additionalChecks;
    };

    // File integrity database entry
    struct FileIntegrityEntry {
        std::string filePath;
        std::string expectedHash;
        HashAlgorithm algorithm;
        DWORD expectedSize;
        bool isCritical;
        bool isProtected;
        std::string version;
        std::string description;
        std::string lastUpdated;
        std::vector<std::string> allowedHashes; // For multiple valid versions
    };

    // Client session information
    struct ClientSession {
        std::string clientId;
        std::string sessionToken;
        std::string ipAddress;
        std::chrono::system_clock::time_point lastActivity;
        std::chrono::system_clock::time_point sessionStart;
        DWORD validationCount;
        DWORD violationCount;
        bool isAuthenticated;
        bool isTrusted;
        std::string clientVersion;
        std::string hwid; // Hardware ID for additional validation
    };

    // Server configuration
    struct ServerValidationConfig {
        // Server settings
        std::string serverAddress = "0.0.0.0";
        DWORD serverPort = 8443;
        bool enableSSL = true;
        std::string certificatePath = "";
        std::string privateKeyPath = "";
        
        // Security settings
        bool enableSignatureValidation = true;
        bool enableHWIDValidation = true;
        bool enableRateLimiting = true;
        DWORD maxRequestsPerMinute = 100;
        DWORD sessionTimeoutMinutes = 30;
        
        // Database settings
        std::string databasePath = "integrity_database.json";
        bool enableDatabaseEncryption = true;
        std::string encryptionKey = "";
        
        // Validation settings
        float confidenceThreshold = 0.8f;
        bool enableHeuristicValidation = true;
        bool enableCrossValidation = true;
        DWORD maxConcurrentClients = 1000;
        
        // Logging settings
        bool enableDetailedLogging = true;
        bool enableAuditLog = true;
        std::string logPath = "server_logs/";
    };

    // Callback types
    using ValidationCallback = std::function<void(const ValidationRequest&, const ValidationResponse&)>;
    using SecurityViolationCallback = std::function<void(const std::string& clientId, const std::string& violation)>;
    using ClientConnectedCallback = std::function<void(const std::string& clientId)>;

    class FileIntegrityValidator {
    public:
        FileIntegrityValidator();
        ~FileIntegrityValidator();

        // Core operations
        bool Initialize(const ServerValidationConfig& config);
        void Shutdown();
        bool IsInitialized() const { return m_initialized; }

        // Server operations
        bool StartServer();
        void StopServer();
        bool IsServerRunning() const { return m_serverRunning; }

        // Validation operations
        ValidationResponse ValidateFileIntegrity(const ValidationRequest& request);
        bool ValidateClientSession(const std::string& clientId, const std::string& sessionToken);
        bool AuthenticateClient(const std::string& clientId, const std::string& credentials);

        // Database management
        bool LoadIntegrityDatabase(const std::string& filePath);
        bool SaveIntegrityDatabase(const std::string& filePath) const;
        bool AddFileEntry(const FileIntegrityEntry& entry);
        bool RemoveFileEntry(const std::string& filePath);
        bool UpdateFileEntry(const FileIntegrityEntry& entry);
        std::vector<FileIntegrityEntry> GetAllFileEntries() const;

        // Client session management
        bool CreateClientSession(const std::string& clientId, const std::string& ipAddress);
        bool UpdateClientSession(const std::string& clientId);
        bool RemoveClientSession(const std::string& clientId);
        std::vector<ClientSession> GetActiveSessions() const;
        void CleanupExpiredSessions();

        // Security operations
        std::string GenerateSessionToken(const std::string& clientId);
        bool ValidateRequestSignature(const ValidationRequest& request);
        std::string SignResponse(const ValidationResponse& response);
        bool ValidateHWID(const std::string& clientId, const std::string& hwid);

        // Statistics and monitoring
        struct ServerStatistics {
            std::atomic<DWORD> totalRequests{0};
            std::atomic<DWORD> validRequests{0};
            std::atomic<DWORD> invalidRequests{0};
            std::atomic<DWORD> securityViolations{0};
            std::atomic<DWORD> activeClients{0};
            std::atomic<DWORD> totalClients{0};
            DWORD serverStartTime{0};
            DWORD lastRequestTime{0};
        };

        ServerStatistics GetStatistics() const;
        void ResetStatistics();
        std::string GetStatusReport() const;

        // Configuration
        void UpdateConfig(const ServerValidationConfig& config);
        ServerValidationConfig GetConfig() const;

        // Callbacks
        void SetValidationCallback(ValidationCallback callback);
        void SetSecurityViolationCallback(SecurityViolationCallback callback);
        void SetClientConnectedCallback(ClientConnectedCallback callback);

        // Advanced features
        bool EnableRateLimiting(const std::string& clientId, DWORD maxRequests);
        bool BlacklistClient(const std::string& clientId, const std::string& reason);
        bool WhitelistClient(const std::string& clientId);
        std::vector<std::string> GetBlacklistedClients() const;
        bool ExportAuditLog(const std::string& filePath) const;

    private:
        // Core validation methods
        bool ValidateFileInternal(const ValidationRequest& request, ValidationResponse& response);
        bool CheckFileInDatabase(const std::string& filePath, const std::string& hash, HashAlgorithm algorithm);
        bool PerformHeuristicValidation(const ValidationRequest& request);
        bool PerformCrossValidation(const ValidationRequest& request);

        // Security methods
        bool ValidateClientCredentials(const std::string& clientId, const std::string& credentials);
        bool CheckRateLimit(const std::string& clientId);
        bool IsClientBlacklisted(const std::string& clientId);
        bool IsClientTrusted(const std::string& clientId);

        // Database operations
        bool LoadDatabaseInternal();
        bool SaveDatabaseInternal() const;
        bool EncryptDatabase(const std::string& data, std::string& encrypted) const;
        bool DecryptDatabase(const std::string& encrypted, std::string& data) const;

        // Network operations
        static DWORD WINAPI ServerThreadProc(LPVOID lpParam);
        void ServerLoop();
        bool HandleClientConnection(SOCKET clientSocket);
        bool ProcessValidationRequest(const std::string& requestData, std::string& responseData);

        // Utility methods
        std::string GenerateRandomToken(size_t length = 32);
        std::string CalculateHMAC(const std::string& data, const std::string& key);
        std::string GetCurrentTimestamp();
        bool ParseValidationRequest(const std::string& data, ValidationRequest& request);
        std::string SerializeValidationResponse(const ValidationResponse& response);

        // Logging and error handling
        void LogValidation(const ValidationRequest& request, const ValidationResponse& response);
        void LogSecurityViolation(const std::string& clientId, const std::string& violation);
        void LogError(const std::string& error);
        void HandleError(const std::string& error);

        // Member variables
        bool m_initialized;
        bool m_serverRunning;
        bool m_shouldStop;
        ServerValidationConfig m_config;

        // Database
        std::unordered_map<std::string, FileIntegrityEntry> m_integrityDatabase;
        mutable std::mutex m_databaseMutex;

        // Client sessions
        std::unordered_map<std::string, ClientSession> m_clientSessions;
        mutable std::mutex m_sessionsMutex;

        // Security
        std::unordered_map<std::string, std::chrono::system_clock::time_point> m_rateLimitMap;
        std::unordered_set<std::string> m_blacklistedClients;
        std::unordered_set<std::string> m_whitelistedClients;
        mutable std::mutex m_securityMutex;

        // Threading
        HANDLE m_serverThread;
        SOCKET m_serverSocket;

        // Statistics
        mutable ServerStatistics m_statistics;

        // Callbacks
        ValidationCallback m_validationCallback;
        SecurityViolationCallback m_securityViolationCallback;
        ClientConnectedCallback m_clientConnectedCallback;
        mutable std::mutex m_callbackMutex;

        // Cryptographic key for HMAC
        std::string m_hmacKey;
    };

} // namespace GarudaHS

#endif // FILEINTEGRITYVALIDATOR_H
