#include "../include/FileIntegrityValidator.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <random>
#include <iomanip>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <json/json.h>

#pragma comment(lib, "ws2_32.lib")

namespace GarudaHS {

    FileIntegrityValidator::FileIntegrityValidator()
        : m_initialized(false)
        , m_serverRunning(false)
        , m_shouldStop(false)
        , m_serverThread(nullptr)
        , m_serverSocket(INVALID_SOCKET)
    {
        // Generate HMAC key
        m_hmacKey = GenerateRandomToken(64);
    }

    FileIntegrityValidator::~FileIntegrityValidator() {
        Shutdown();
    }

    bool FileIntegrityValidator::Initialize(const ServerValidationConfig& config) {
        try {
            if (m_initialized) {
                std::cout << "FileIntegrityValidator already initialized" << std::endl;
                return true;
            }

            m_config = config;

            // Initialize Winsock
            WSADATA wsaData;
            int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
            if (result != 0) {
                HandleError("WSAStartup failed: " + std::to_string(result));
                return false;
            }

            // Load integrity database
            if (!LoadIntegrityDatabase(m_config.databasePath)) {
                std::cout << "Warning: Could not load integrity database, starting with empty database" << std::endl;
            }

            // Load default file entries if database is empty
            if (m_integrityDatabase.empty()) {
                LoadDefaultFileEntries();
            }

            m_statistics.serverStartTime = GetTickCount();
            m_initialized = true;
            
            std::cout << "FileIntegrityValidator initialized successfully" << std::endl;
            return true;

        } catch (const std::exception& e) {
            HandleError("Initialize failed: " + std::string(e.what()));
            return false;
        }
    }

    void FileIntegrityValidator::Shutdown() {
        try {
            if (!m_initialized) {
                return;
            }

            // Stop server
            StopServer();

            // Save database
            SaveIntegrityDatabase(m_config.databasePath);

            // Cleanup Winsock
            WSACleanup();

            m_initialized = false;
            std::cout << "FileIntegrityValidator shutdown completed" << std::endl;

        } catch (const std::exception& e) {
            HandleError("Shutdown error: " + std::string(e.what()));
        }
    }

    bool FileIntegrityValidator::StartServer() {
        try {
            if (m_serverRunning) {
                return true;
            }

            // Create server socket
            m_serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (m_serverSocket == INVALID_SOCKET) {
                HandleError("Failed to create server socket");
                return false;
            }

            // Set socket options
            int opt = 1;
            setsockopt(m_serverSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

            // Bind socket
            sockaddr_in serverAddr = {};
            serverAddr.sin_family = AF_INET;
            serverAddr.sin_port = htons(static_cast<u_short>(m_config.serverPort));
            inet_pton(AF_INET, m_config.serverAddress.c_str(), &serverAddr.sin_addr);

            if (bind(m_serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
                HandleError("Failed to bind server socket");
                closesocket(m_serverSocket);
                m_serverSocket = INVALID_SOCKET;
                return false;
            }

            // Listen for connections
            if (listen(m_serverSocket, SOMAXCONN) == SOCKET_ERROR) {
                HandleError("Failed to listen on server socket");
                closesocket(m_serverSocket);
                m_serverSocket = INVALID_SOCKET;
                return false;
            }

            // Start server thread
            m_shouldStop = false;
            m_serverThread = CreateThread(nullptr, 0, ServerThreadProc, this, 0, nullptr);
            if (!m_serverThread) {
                HandleError("Failed to create server thread");
                closesocket(m_serverSocket);
                m_serverSocket = INVALID_SOCKET;
                return false;
            }

            m_serverRunning = true;
            std::cout << "Server started on " << m_config.serverAddress << ":" << m_config.serverPort << std::endl;
            return true;

        } catch (const std::exception& e) {
            HandleError("StartServer failed: " + std::string(e.what()));
            return false;
        }
    }

    void FileIntegrityValidator::StopServer() {
        try {
            if (!m_serverRunning) {
                return;
            }

            m_shouldStop = true;

            // Close server socket
            if (m_serverSocket != INVALID_SOCKET) {
                closesocket(m_serverSocket);
                m_serverSocket = INVALID_SOCKET;
            }

            // Wait for server thread
            if (m_serverThread) {
                WaitForSingleObject(m_serverThread, 5000);
                CloseHandle(m_serverThread);
                m_serverThread = nullptr;
            }

            m_serverRunning = false;
            std::cout << "Server stopped" << std::endl;

        } catch (const std::exception& e) {
            HandleError("StopServer error: " + std::string(e.what()));
        }
    }

    ValidationResponse FileIntegrityValidator::ValidateFileIntegrity(const ValidationRequest& request) {
        ValidationResponse response = {};
        response.isValid = false;
        response.isAuthorized = false;
        response.confidence = 0.0f;
        response.serverTimestamp = GetCurrentTimestamp();

        try {
            m_statistics.totalRequests.fetch_add(1);

            // Validate client session
            if (!ValidateClientSession(request.clientId, request.sessionToken)) {
                response.reason = "Invalid client session";
                LogSecurityViolation(request.clientId, "Invalid session token");
                return response;
            }

            // Check rate limiting
            if (m_config.enableRateLimiting && !CheckRateLimit(request.clientId)) {
                response.reason = "Rate limit exceeded";
                LogSecurityViolation(request.clientId, "Rate limit exceeded");
                return response;
            }

            // Check if client is blacklisted
            if (IsClientBlacklisted(request.clientId)) {
                response.reason = "Client is blacklisted";
                LogSecurityViolation(request.clientId, "Blacklisted client access attempt");
                return response;
            }

            // Validate request signature
            if (m_config.enableSignatureValidation && !ValidateRequestSignature(request)) {
                response.reason = "Invalid request signature";
                LogSecurityViolation(request.clientId, "Invalid request signature");
                return response;
            }

            response.isAuthorized = true;

            // Perform file integrity validation
            if (ValidateFileInternal(request, response)) {
                m_statistics.validRequests.fetch_add(1);
            } else {
                m_statistics.invalidRequests.fetch_add(1);
            }

            // Update client session
            UpdateClientSession(request.clientId);

            // Sign response
            response.responseSignature = SignResponse(response);

            // Log validation
            LogValidation(request, response);

            // Trigger callback
            {
                std::lock_guard<std::mutex> lock(m_callbackMutex);
                if (m_validationCallback) {
                    m_validationCallback(request, response);
                }
            }

        } catch (const std::exception& e) {
            response.reason = "Server error during validation";
            HandleError("ValidateFileIntegrity failed: " + std::string(e.what()));
        }

        return response;
    }

    bool FileIntegrityValidator::ValidateFileInternal(const ValidationRequest& request, ValidationResponse& response) {
        try {
            // Check if file exists in database
            {
                std::lock_guard<std::mutex> lock(m_databaseMutex);
                auto it = m_integrityDatabase.find(request.filePath);
                if (it == m_integrityDatabase.end()) {
                    response.reason = "File not found in integrity database";
                    response.confidence = 0.0f;
                    return false;
                }

                const FileIntegrityEntry& entry = it->second;

                // Check algorithm match
                if (entry.algorithm != request.algorithm) {
                    response.reason = "Hash algorithm mismatch";
                    response.confidence = 0.2f;
                    return false;
                }

                // Check file size if available
                if (entry.expectedSize > 0 && request.fileSize != entry.expectedSize) {
                    response.reason = "File size mismatch";
                    response.confidence = 0.3f;
                    response.additionalChecks.push_back("Size validation failed");
                }

                // Check primary hash
                if (entry.expectedHash == request.fileHash) {
                    response.isValid = true;
                    response.reason = "File integrity verified";
                    response.confidence = 1.0f;
                    return true;
                }

                // Check alternative hashes (for multiple valid versions)
                for (const std::string& allowedHash : entry.allowedHashes) {
                    if (allowedHash == request.fileHash) {
                        response.isValid = true;
                        response.reason = "File integrity verified (alternative version)";
                        response.confidence = 0.95f;
                        return true;
                    }
                }

                // Hash mismatch
                response.reason = "File hash mismatch - possible tampering detected";
                response.confidence = 0.1f;
                
                if (entry.isCritical) {
                    response.additionalChecks.push_back("Critical file modified");
                    LogSecurityViolation(request.clientId, "Critical file tampering: " + request.filePath);
                }

                return false;
            }

        } catch (const std::exception& e) {
            response.reason = "Internal validation error";
            response.confidence = 0.0f;
            HandleError("ValidateFileInternal failed: " + std::string(e.what()));
            return false;
        }
    }

    void FileIntegrityValidator::LoadDefaultFileEntries() {
        // Add some default critical files
        FileIntegrityEntry gameExe = {};
        gameExe.filePath = "game.exe";
        gameExe.expectedHash = ""; // Would be calculated during deployment
        gameExe.algorithm = HashAlgorithm::SHA256;
        gameExe.expectedSize = 0;
        gameExe.isCritical = true;
        gameExe.isProtected = true;
        gameExe.version = "1.0";
        gameExe.description = "Main game executable";
        gameExe.lastUpdated = GetCurrentTimestamp();
        
        AddFileEntry(gameExe);

        std::cout << "Loaded default file entries" << std::endl;
    }

    // Session management implementation
    bool FileIntegrityValidator::CreateClientSession(const std::string& clientId, const std::string& ipAddress) {
        try {
            std::lock_guard<std::mutex> lock(m_sessionsMutex);

            ClientSession session = {};
            session.clientId = clientId;
            session.sessionToken = GenerateSessionToken(clientId);
            session.ipAddress = ipAddress;
            session.sessionStart = std::chrono::system_clock::now();
            session.lastActivity = session.sessionStart;
            session.validationCount = 0;
            session.violationCount = 0;
            session.isAuthenticated = true;
            session.isTrusted = IsClientTrusted(clientId);
            session.clientVersion = "1.0"; // Would be provided by client

            m_clientSessions[clientId] = session;
            m_statistics.activeClients.fetch_add(1);
            m_statistics.totalClients.fetch_add(1);

            std::cout << "Created session for client: " << clientId << std::endl;
            return true;

        } catch (const std::exception& e) {
            HandleError("CreateClientSession failed: " + std::string(e.what()));
            return false;
        }
    }

    bool FileIntegrityValidator::ValidateClientSession(const std::string& clientId, const std::string& sessionToken) {
        try {
            std::lock_guard<std::mutex> lock(m_sessionsMutex);

            auto it = m_clientSessions.find(clientId);
            if (it == m_clientSessions.end()) {
                return false;
            }

            ClientSession& session = it->second;

            // Check session token
            if (session.sessionToken != sessionToken) {
                return false;
            }

            // Check session timeout
            auto now = std::chrono::system_clock::now();
            auto sessionAge = std::chrono::duration_cast<std::chrono::minutes>(now - session.sessionStart);
            if (sessionAge.count() > m_config.sessionTimeoutMinutes) {
                m_clientSessions.erase(it);
                m_statistics.activeClients.fetch_sub(1);
                return false;
            }

            return session.isAuthenticated;

        } catch (const std::exception& e) {
            HandleError("ValidateClientSession failed: " + std::string(e.what()));
            return false;
        }
    }

    bool FileIntegrityValidator::UpdateClientSession(const std::string& clientId) {
        try {
            std::lock_guard<std::mutex> lock(m_sessionsMutex);

            auto it = m_clientSessions.find(clientId);
            if (it != m_clientSessions.end()) {
                it->second.lastActivity = std::chrono::system_clock::now();
                it->second.validationCount++;
                return true;
            }

            return false;

        } catch (const std::exception& e) {
            HandleError("UpdateClientSession failed: " + std::string(e.what()));
            return false;
        }
    }

    void FileIntegrityValidator::CleanupExpiredSessions() {
        try {
            std::lock_guard<std::mutex> lock(m_sessionsMutex);

            auto now = std::chrono::system_clock::now();
            auto it = m_clientSessions.begin();

            while (it != m_clientSessions.end()) {
                auto sessionAge = std::chrono::duration_cast<std::chrono::minutes>(now - it->second.sessionStart);
                if (sessionAge.count() > m_config.sessionTimeoutMinutes) {
                    std::cout << "Removing expired session for client: " << it->first << std::endl;
                    it = m_clientSessions.erase(it);
                    m_statistics.activeClients.fetch_sub(1);
                } else {
                    ++it;
                }
            }

        } catch (const std::exception& e) {
            HandleError("CleanupExpiredSessions failed: " + std::string(e.what()));
        }
    }

    // Security methods implementation
    std::string FileIntegrityValidator::GenerateSessionToken(const std::string& clientId) {
        std::string data = clientId + GetCurrentTimestamp() + GenerateRandomToken(16);
        return CalculateHMAC(data, m_hmacKey);
    }

    bool FileIntegrityValidator::ValidateRequestSignature(const ValidationRequest& request) {
        try {
            // Reconstruct the data that should have been signed
            std::string dataToSign = request.clientId + request.filePath + request.fileHash +
                                   std::to_string(static_cast<int>(request.algorithm)) +
                                   std::to_string(request.fileSize) + request.timestamp;

            std::string expectedSignature = CalculateHMAC(dataToSign, m_hmacKey);
            return (expectedSignature == request.signature);

        } catch (const std::exception& e) {
            HandleError("ValidateRequestSignature failed: " + std::string(e.what()));
            return false;
        }
    }

    std::string FileIntegrityValidator::SignResponse(const ValidationResponse& response) {
        try {
            std::string dataToSign = std::to_string(response.isValid) +
                                   std::to_string(response.isAuthorized) +
                                   response.reason +
                                   std::to_string(response.confidence) +
                                   response.serverTimestamp;

            return CalculateHMAC(dataToSign, m_hmacKey);

        } catch (const std::exception& e) {
            HandleError("SignResponse failed: " + std::string(e.what()));
            return "";
        }
    }

    bool FileIntegrityValidator::CheckRateLimit(const std::string& clientId) {
        try {
            std::lock_guard<std::mutex> lock(m_securityMutex);

            auto now = std::chrono::system_clock::now();
            auto it = m_rateLimitMap.find(clientId);

            if (it == m_rateLimitMap.end()) {
                m_rateLimitMap[clientId] = now;
                return true;
            }

            auto timeDiff = std::chrono::duration_cast<std::chrono::minutes>(now - it->second);
            if (timeDiff.count() >= 1) {
                it->second = now;
                return true;
            }

            // For simplicity, we're just checking if more than 1 minute has passed
            // A real implementation would track request counts per time window
            return false;

        } catch (const std::exception& e) {
            HandleError("CheckRateLimit failed: " + std::string(e.what()));
            return false;
        }
    }

    bool FileIntegrityValidator::IsClientBlacklisted(const std::string& clientId) {
        std::lock_guard<std::mutex> lock(m_securityMutex);
        return m_blacklistedClients.find(clientId) != m_blacklistedClients.end();
    }

    bool FileIntegrityValidator::IsClientTrusted(const std::string& clientId) {
        std::lock_guard<std::mutex> lock(m_securityMutex);
        return m_whitelistedClients.find(clientId) != m_whitelistedClients.end();
    }

    // Utility methods implementation
    std::string FileIntegrityValidator::GenerateRandomToken(size_t length) {
        const std::string chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, static_cast<int>(chars.size() - 1));

        std::string token;
        token.reserve(length);
        for (size_t i = 0; i < length; ++i) {
            token += chars[dis(gen)];
        }
        return token;
    }

    std::string FileIntegrityValidator::CalculateHMAC(const std::string& data, const std::string& key) {
        try {
            unsigned char result[EVP_MAX_MD_SIZE];
            unsigned int resultLen = 0;

            HMAC(EVP_sha256(), key.c_str(), static_cast<int>(key.length()),
                 reinterpret_cast<const unsigned char*>(data.c_str()), data.length(),
                 result, &resultLen);

            std::stringstream ss;
            for (unsigned int i = 0; i < resultLen; i++) {
                ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(result[i]);
            }

            return ss.str();

        } catch (const std::exception& e) {
            HandleError("CalculateHMAC failed: " + std::string(e.what()));
            return "";
        }
    }

    std::string FileIntegrityValidator::GetCurrentTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);

        std::stringstream ss;
        ss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%SZ");
        return ss.str();
    }

    // Logging methods implementation
    void FileIntegrityValidator::LogValidation(const ValidationRequest& request, const ValidationResponse& response) {
        if (m_config.enableDetailedLogging) {
            std::cout << "[VALIDATION] Client: " << request.clientId
                     << " File: " << request.filePath
                     << " Valid: " << (response.isValid ? "YES" : "NO")
                     << " Confidence: " << response.confidence << std::endl;
        }
    }

    void FileIntegrityValidator::LogSecurityViolation(const std::string& clientId, const std::string& violation) {
        std::cout << "[SECURITY] Client: " << clientId << " Violation: " << violation << std::endl;

        m_statistics.securityViolations.fetch_add(1);

        // Trigger callback
        {
            std::lock_guard<std::mutex> lock(m_callbackMutex);
            if (m_securityViolationCallback) {
                m_securityViolationCallback(clientId, violation);
            }
        }
    }

    void FileIntegrityValidator::HandleError(const std::string& error) {
        std::cerr << "[ERROR] FileIntegrityValidator: " << error << std::endl;
    }

    // Database management implementation
    bool FileIntegrityValidator::AddFileEntry(const FileIntegrityEntry& entry) {
        try {
            std::lock_guard<std::mutex> lock(m_databaseMutex);
            m_integrityDatabase[entry.filePath] = entry;
            return true;

        } catch (const std::exception& e) {
            HandleError("AddFileEntry failed: " + std::string(e.what()));
            return false;
        }
    }

    bool FileIntegrityValidator::LoadIntegrityDatabase(const std::string& filePath) {
        try {
            std::ifstream file(filePath);
            if (!file.is_open()) {
                return false;
            }

            Json::Value root;
            file >> root;

            std::lock_guard<std::mutex> lock(m_databaseMutex);
            m_integrityDatabase.clear();

            for (const auto& item : root["files"]) {
                FileIntegrityEntry entry = {};
                entry.filePath = item["filePath"].asString();
                entry.expectedHash = item["expectedHash"].asString();
                entry.algorithm = static_cast<HashAlgorithm>(item["algorithm"].asInt());
                entry.expectedSize = item["expectedSize"].asUInt();
                entry.isCritical = item["isCritical"].asBool();
                entry.isProtected = item["isProtected"].asBool();
                entry.version = item["version"].asString();
                entry.description = item["description"].asString();
                entry.lastUpdated = item["lastUpdated"].asString();

                for (const auto& hash : item["allowedHashes"]) {
                    entry.allowedHashes.push_back(hash.asString());
                }

                m_integrityDatabase[entry.filePath] = entry;
            }

            std::cout << "Loaded " << m_integrityDatabase.size() << " file entries from database" << std::endl;
            return true;

        } catch (const std::exception& e) {
            HandleError("LoadIntegrityDatabase failed: " + std::string(e.what()));
            return false;
        }
    }

} // namespace GarudaHS
