#include "../include/FileIntegrityChecker.h"
#include "../include/Logger.h"
#include <iostream>
#include <fstream>
#include <cassert>
#include <filesystem>

using namespace GarudaHS;

class FileIntegrityTester {
private:
    std::shared_ptr<Logger> m_logger;
    std::unique_ptr<FileIntegrityChecker> m_checker;
    std::string m_testDir;

public:
    FileIntegrityTester() {
        m_logger = std::make_shared<Logger>();
        m_checker = std::make_unique<FileIntegrityChecker>(m_logger);
        m_testDir = "test_files/";
        
        // Create test directory
        std::filesystem::create_directories(m_testDir);
    }

    ~FileIntegrityTester() {
        // Cleanup test files
        try {
            std::filesystem::remove_all(m_testDir);
        } catch (...) {
            // Ignore cleanup errors
        }
    }

    bool RunAllTests() {
        std::cout << "=== File Integrity Checker Tests ===" << std::endl;
        
        bool allPassed = true;
        
        allPassed &= TestInitialization();
        allPassed &= TestFileCreationAndHashing();
        allPassed &= TestFileModificationDetection();
        allPassed &= TestMissingFileDetection();
        allPassed &= TestMultipleHashAlgorithms();
        allPassed &= TestCacheSystem();
        allPassed &= TestCriticalFileMonitoring();
        allPassed &= TestPerformance();
        
        std::cout << "\n=== Test Results ===" << std::endl;
        std::cout << "All tests " << (allPassed ? "PASSED" : "FAILED") << std::endl;
        
        return allPassed;
    }

private:
    bool TestInitialization() {
        std::cout << "\n[TEST] Initialization..." << std::endl;
        
        FileIntegrityConfig config = {};
        config.enableRealTimeMonitoring = false; // Disable for testing
        config.enablePeriodicScanning = false;
        config.enableCaching = true;
        config.enableMultiThreading = false;
        
        bool result = m_checker->Initialize(config);
        
        std::cout << "Initialization: " << (result ? "PASS" : "FAIL") << std::endl;
        return result;
    }

    bool TestFileCreationAndHashing() {
        std::cout << "\n[TEST] File Creation and Hashing..." << std::endl;
        
        // Create test file
        std::string testFile = m_testDir + "test_file.txt";
        std::string testContent = "This is a test file for integrity checking.";
        
        std::ofstream file(testFile);
        file << testContent;
        file.close();
        
        // Calculate hash
        std::string hash = m_checker->CalculateFileHash(testFile, HashAlgorithm::SHA256);
        
        bool result = !hash.empty() && hash.length() == 64; // SHA256 is 64 hex chars
        
        std::cout << "File creation and hashing: " << (result ? "PASS" : "FAIL") << std::endl;
        if (result) {
            std::cout << "  Hash: " << hash << std::endl;
        }
        
        return result;
    }

    bool TestFileModificationDetection() {
        std::cout << "\n[TEST] File Modification Detection..." << std::endl;
        
        // Create test file
        std::string testFile = m_testDir + "modify_test.txt";
        std::string originalContent = "Original content";
        
        std::ofstream file(testFile);
        file << originalContent;
        file.close();
        
        // Calculate original hash
        std::string originalHash = m_checker->CalculateFileHash(testFile, HashAlgorithm::SHA256);
        
        // Add file to monitoring
        FileEntry entry = {};
        entry.filePath = testFile;
        entry.expectedHash = originalHash;
        entry.algorithm = HashAlgorithm::SHA256;
        entry.isCritical = true;
        entry.isProtected = false;
        entry.description = "Test file for modification detection";
        
        m_checker->AddFileToMonitor(entry);
        
        // Check original file (should be valid)
        FileIntegrityResult result1 = m_checker->CheckFile(testFile, HashAlgorithm::SHA256);
        bool originalValid = (result1.status == IntegrityStatus::VALID);
        
        // Modify file
        std::ofstream modFile(testFile);
        modFile << "Modified content";
        modFile.close();
        
        // Check modified file (should be invalid)
        FileIntegrityResult result2 = m_checker->CheckFile(testFile, HashAlgorithm::SHA256);
        bool modifiedInvalid = (result2.status == IntegrityStatus::MODIFIED);
        
        bool result = originalValid && modifiedInvalid;
        
        std::cout << "File modification detection: " << (result ? "PASS" : "FAIL") << std::endl;
        std::cout << "  Original status: " << static_cast<int>(result1.status) << std::endl;
        std::cout << "  Modified status: " << static_cast<int>(result2.status) << std::endl;
        
        return result;
    }

    bool TestMissingFileDetection() {
        std::cout << "\n[TEST] Missing File Detection..." << std::endl;
        
        std::string missingFile = m_testDir + "missing_file.txt";
        
        // Try to check non-existent file
        FileIntegrityResult result = m_checker->CheckFile(missingFile, HashAlgorithm::SHA256);
        
        bool success = (result.status == IntegrityStatus::MISSING);
        
        std::cout << "Missing file detection: " << (success ? "PASS" : "FAIL") << std::endl;
        std::cout << "  Status: " << static_cast<int>(result.status) << std::endl;
        
        return success;
    }

    bool TestMultipleHashAlgorithms() {
        std::cout << "\n[TEST] Multiple Hash Algorithms..." << std::endl;
        
        // Create test file
        std::string testFile = m_testDir + "hash_test.txt";
        std::string content = "Test content for multiple hash algorithms";
        
        std::ofstream file(testFile);
        file << content;
        file.close();
        
        // Test different algorithms
        std::string md5Hash = m_checker->CalculateFileHash(testFile, HashAlgorithm::MD5);
        std::string sha256Hash = m_checker->CalculateFileHash(testFile, HashAlgorithm::SHA256);
        std::string crc32Hash = m_checker->CalculateFileHash(testFile, HashAlgorithm::CRC32);
        
        bool result = !md5Hash.empty() && !sha256Hash.empty() && !crc32Hash.empty() &&
                     md5Hash.length() == 32 &&    // MD5 is 32 hex chars
                     sha256Hash.length() == 64 &&  // SHA256 is 64 hex chars
                     crc32Hash.length() == 8;      // CRC32 is 8 hex chars
        
        std::cout << "Multiple hash algorithms: " << (result ? "PASS" : "FAIL") << std::endl;
        std::cout << "  MD5 length: " << md5Hash.length() << std::endl;
        std::cout << "  SHA256 length: " << sha256Hash.length() << std::endl;
        std::cout << "  CRC32 length: " << crc32Hash.length() << std::endl;
        
        return result;
    }

    bool TestCacheSystem() {
        std::cout << "\n[TEST] Cache System..." << std::endl;
        
        // Create test file
        std::string testFile = m_testDir + "cache_test.txt";
        std::string content = "Cache test content";
        
        std::ofstream file(testFile);
        file << content;
        file.close();
        
        // First calculation (should miss cache)
        DWORD start1 = GetTickCount();
        std::string hash1 = m_checker->CalculateFileHash(testFile, HashAlgorithm::SHA256);
        DWORD time1 = GetTickCount() - start1;
        
        // Second calculation (should hit cache)
        DWORD start2 = GetTickCount();
        std::string hash2 = m_checker->CalculateFileHash(testFile, HashAlgorithm::SHA256);
        DWORD time2 = GetTickCount() - start2;
        
        bool result = (hash1 == hash2) && (time2 <= time1); // Cache should be faster or equal
        
        std::cout << "Cache system: " << (result ? "PASS" : "FAIL") << std::endl;
        std::cout << "  First calculation: " << time1 << "ms" << std::endl;
        std::cout << "  Second calculation: " << time2 << "ms" << std::endl;
        std::cout << "  Hashes match: " << (hash1 == hash2 ? "YES" : "NO") << std::endl;
        
        return result;
    }

    bool TestCriticalFileMonitoring() {
        std::cout << "\n[TEST] Critical File Monitoring..." << std::endl;
        
        // Create critical test file
        std::string criticalFile = m_testDir + "critical.exe";
        std::string content = "Critical executable content";
        
        std::ofstream file(criticalFile);
        file << content;
        file.close();
        
        // Calculate hash and add as critical file
        std::string hash = m_checker->CalculateFileHash(criticalFile, HashAlgorithm::SHA256);
        
        FileEntry entry = {};
        entry.filePath = criticalFile;
        entry.expectedHash = hash;
        entry.algorithm = HashAlgorithm::SHA256;
        entry.isCritical = true;
        entry.isProtected = true;
        entry.description = "Critical test file";
        
        bool addResult = m_checker->AddFileToMonitor(entry);
        
        // Check critical files
        auto criticalResults = m_checker->CheckCriticalFiles();
        
        bool result = addResult && !criticalResults.empty() && 
                     criticalResults[0].status == IntegrityStatus::VALID;
        
        std::cout << "Critical file monitoring: " << (result ? "PASS" : "FAIL") << std::endl;
        std::cout << "  File added: " << (addResult ? "YES" : "NO") << std::endl;
        std::cout << "  Critical files found: " << criticalResults.size() << std::endl;
        
        return result;
    }

    bool TestPerformance() {
        std::cout << "\n[TEST] Performance..." << std::endl;
        
        const int NUM_FILES = 10;
        std::vector<std::string> testFiles;
        
        // Create multiple test files
        for (int i = 0; i < NUM_FILES; i++) {
            std::string fileName = m_testDir + "perf_test_" + std::to_string(i) + ".txt";
            std::ofstream file(fileName);
            file << "Performance test file " << i << " with some content to hash.";
            file.close();
            testFiles.push_back(fileName);
        }
        
        // Measure performance
        DWORD startTime = GetTickCount();
        
        for (const auto& fileName : testFiles) {
            std::string hash = m_checker->CalculateFileHash(fileName, HashAlgorithm::SHA256);
            if (hash.empty()) {
                std::cout << "Performance test: FAIL (empty hash)" << std::endl;
                return false;
            }
        }
        
        DWORD totalTime = GetTickCount() - startTime;
        double avgTime = static_cast<double>(totalTime) / NUM_FILES;
        
        bool result = (avgTime < 100.0); // Should be less than 100ms per file on average
        
        std::cout << "Performance test: " << (result ? "PASS" : "FAIL") << std::endl;
        std::cout << "  Total time: " << totalTime << "ms" << std::endl;
        std::cout << "  Average per file: " << avgTime << "ms" << std::endl;
        std::cout << "  Files processed: " << NUM_FILES << std::endl;
        
        return result;
    }
};

int main() {
    try {
        FileIntegrityTester tester;
        bool success = tester.RunAllTests();
        
        return success ? 0 : 1;
        
    } catch (const std::exception& e) {
        std::cerr << "Test failed with exception: " << e.what() << std::endl;
        return 1;
    }
}
