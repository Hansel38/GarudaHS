#pragma once

namespace GarudaHS {
namespace Constants {

    // ═══════════════════════════════════════════════════════════
    //                    BUFFER SIZES
    // ═══════════════════════════════════════════════════════════
    
    constexpr size_t MAX_WINDOW_TITLE_LENGTH = 512;
    constexpr size_t MAX_CLASS_NAME_LENGTH = 256;
    constexpr size_t MAX_PROCESS_NAME_LENGTH = 260;
    constexpr size_t MAX_MODULE_PATH_LENGTH = 512;
    constexpr size_t MAX_ERROR_MESSAGE_LENGTH = 1024;
    constexpr size_t MAX_LOG_MESSAGE_LENGTH = 2048;
    
    // ═══════════════════════════════════════════════════════════
    //                    TIMING CONSTANTS
    // ═══════════════════════════════════════════════════════════
    
    constexpr DWORD DEFAULT_SCAN_INTERVAL_MS = 3000;
    constexpr DWORD MIN_SCAN_INTERVAL_MS = 1000;
    constexpr DWORD MAX_SCAN_INTERVAL_MS = 60000;
    constexpr DWORD DEFAULT_THREAD_WAIT_TIMEOUT_MS = 5000;
    constexpr DWORD EMERGENCY_THREAD_WAIT_TIMEOUT_MS = 2000;
    constexpr DWORD ERROR_RECOVERY_SLEEP_MS = 1000;
    constexpr DWORD SHUTDOWN_GRACE_PERIOD_MS = 10000;
    
    // ═══════════════════════════════════════════════════════════
    //                    ANTI-DEBUG CONSTANTS
    // ═══════════════════════════════════════════════════════════
    
    constexpr DWORD PROCESS_DEBUG_FLAGS = 0x1f;
    constexpr DWORD PEB_OFFSET_X64 = 0x60;
    constexpr DWORD PEB_OFFSET_X86 = 0x30;
    constexpr DWORD NT_GLOBAL_FLAG_MASK = 0x70;
    constexpr DWORD DR7_REGISTER_MASK = 0xFF;
    constexpr DWORD HEAP_DEBUG_FLAGS_1 = 0x2;
    constexpr DWORD HEAP_DEBUG_FLAGS_2 = 0x8000;
    constexpr DWORD HEAP_FORCE_FLAGS = 0x40000060;
    constexpr DWORD HEAP_FLAGS_OFFSET = 0x40;
    constexpr DWORD HEAP_FORCE_FLAGS_OFFSET = 0x44;
    
    // System call opcodes (Windows 10/11 NtQueryInformationProcess)
    constexpr BYTE EXPECTED_OPCODES[] = {0x4C, 0x8B, 0xD1};
    constexpr size_t OPCODE_LENGTH = 3;
    
    // Timing detection
    constexpr DWORD DEFAULT_TIMING_THRESHOLD_MS = 10;
    constexpr DWORD MAX_TIMING_VARIANCE_MS = 5;
    constexpr size_t TIMING_BASELINE_SAMPLES = 10;
    constexpr size_t TIMING_LOOP_ITERATIONS = 1000;
    
    // ═══════════════════════════════════════════════════════════
    //                    CONFIDENCE SCORES
    // ═══════════════════════════════════════════════════════════
    
    constexpr float DEFAULT_CONFIDENCE_THRESHOLD = 0.8f;
    constexpr float HIGH_CONFIDENCE_SCORE = 0.9f;
    constexpr float MEDIUM_CONFIDENCE_SCORE = 0.7f;
    constexpr float LOW_CONFIDENCE_SCORE = 0.5f;
    constexpr float CRITICAL_CONFIDENCE_SCORE = 0.95f;
    
    // Anti-Debug confidence scores
    constexpr float BASIC_API_CONFIDENCE = 0.9f;
    constexpr float NT_QUERY_CONFIDENCE = 0.95f;
    constexpr float PEB_FLAGS_CONFIDENCE = 0.9f;
    constexpr float HARDWARE_BREAKPOINTS_CONFIDENCE = 0.85f;
    constexpr float TIMING_ATTACKS_CONFIDENCE = 0.7f;
    constexpr float EXCEPTION_HANDLING_CONFIDENCE = 0.75f;
    constexpr float MEMORY_PROTECTION_CONFIDENCE = 0.8f;
    constexpr float THREAD_CONTEXT_CONFIDENCE = 0.85f;
    constexpr float HEAP_FLAGS_CONFIDENCE = 0.9f;
    constexpr float SYSTEM_CALLS_CONFIDENCE = 0.8f;
    
    // ═══════════════════════════════════════════════════════════
    //                    COLLECTION LIMITS
    // ═══════════════════════════════════════════════════════════
    
    constexpr size_t MAX_DETECTION_HISTORY = 1000;
    constexpr size_t MAX_CACHE_SIZE = 1000;
    constexpr size_t MAX_PROTECTED_THREADS = 50;
    constexpr size_t MAX_MONITORED_PROCESSES = 100;
    constexpr size_t MAX_SCAN_HISTORY = 100;
    constexpr size_t MAX_FEEDBACK_ENTRIES = 1000;
    
    // ═══════════════════════════════════════════════════════════
    //                    THREAD SUSPENSION CONSTANTS
    // ═══════════════════════════════════════════════════════════
    
    constexpr DWORD MAX_SUSPEND_COUNT = 3;
    constexpr DWORD SUSPEND_TIME_THRESHOLD_MS = 5000;
    constexpr DWORD PATTERN_DETECTION_WINDOW_MS = 30000;
    constexpr DWORD SUSPEND_RESUME_MAX_INTERVAL_MS = 1000;
    constexpr DWORD CRITICAL_THREAD_CHECK_INTERVAL_MS = 2000;
    
    // ═══════════════════════════════════════════════════════════
    //                    INJECTION SCANNER CONSTANTS
    // ═══════════════════════════════════════════════════════════
    
    constexpr DWORD INJECTION_SCAN_TIMEOUT_MS = 30000;
    constexpr float INJECTION_CONFIDENCE_THRESHOLD = 0.7f;
    constexpr size_t MAX_PROCESSES_TO_SCAN_FOR_INJECTION = 100;
    
    // Injection method confidence scores
    constexpr float SETWINDOWSHOOK_CONFIDENCE = 0.8f;
    constexpr float MANUAL_DLL_MAPPING_CONFIDENCE = 0.9f;
    constexpr float PROCESS_HOLLOWING_CONFIDENCE = 0.95f;
    constexpr float REFLECTIVE_DLL_CONFIDENCE = 0.9f;
    constexpr float THREAD_HIJACKING_CONFIDENCE = 0.85f;
    constexpr float APC_INJECTION_CONFIDENCE = 0.8f;
    constexpr float ATOM_BOMBING_CONFIDENCE = 0.7f;
    constexpr float PROCESS_DOPPELGANGING_CONFIDENCE = 0.9f;
    constexpr float MANUAL_SYSCALL_CONFIDENCE = 0.85f;
    constexpr float MODULE_STOMPING_CONFIDENCE = 0.9f;
    
    // ═══════════════════════════════════════════════════════════
    //                    OVERLAY SCANNER CONSTANTS
    // ═══════════════════════════════════════════════════════════
    
    constexpr float OVERLAY_CONFIDENCE_THRESHOLD = 0.6f;
    constexpr DWORD OVERLAY_SCAN_INTERVAL_MS = 5000;
    constexpr size_t MAX_MODULE_COUNT = 2048;
    constexpr size_t HOOK_DETECTION_BUFFER_SIZE = 32;
    constexpr BYTE TRANSPARENCY_THRESHOLD = 200;
    constexpr size_t DETECTION_HISTORY_LIMIT = 200;
    
    // Overlay detection confidence scores
    constexpr float DIRECTX_HOOK_CONFIDENCE = 0.75f;
    constexpr float OPENGL_HOOK_CONFIDENCE = 0.75f;
    constexpr float WINDOW_OVERLAY_CONFIDENCE = 0.60f;
    constexpr float SCREEN_CAPTURE_CONFIDENCE = 0.65f;
    constexpr float ENDSCENE_HOOK_CONFIDENCE = 0.80f;
    constexpr float DXGI_HOOK_CONFIDENCE = 0.70f;
    
    // ═══════════════════════════════════════════════════════════
    //                    FALSE POSITIVE PREVENTION
    // ═══════════════════════════════════════════════════════════
    
    constexpr size_t MINIMUM_DETECTION_COUNT = 3;
    constexpr size_t FALSE_POSITIVE_THRESHOLD = 5;
    constexpr float FALSE_POSITIVE_REDUCTION_FACTOR = 0.8f;
    constexpr float DEVELOPMENT_ENVIRONMENT_CONFIDENCE_REDUCTION = 0.5f;
    constexpr DWORD DETECTION_WINDOW_MS = 30000;
    constexpr DWORD SIGNAL_TIMEOUT_MS = 30000;
    
    // ═══════════════════════════════════════════════════════════
    //                    LAYERED DETECTION CONSTANTS
    // ═══════════════════════════════════════════════════════════
    
    constexpr float ACTION_CONFIDENCE_THRESHOLD = 0.8f;
    constexpr float WARNING_CONFIDENCE_THRESHOLD = 0.6f;
    constexpr float LOG_CONFIDENCE_THRESHOLD = 0.3f;
    
    // Signal weights
    constexpr float WEIGHT_PROCESS_DETECTION = 1.0f;
    constexpr float WEIGHT_DEBUGGER_DETECTION = 0.9f;
    constexpr float WEIGHT_THREAD_HIJACK = 0.8f;
    constexpr float WEIGHT_MODULE_INJECTION = 0.7f;
    constexpr float WEIGHT_MEMORY_SCAN = 0.6f;
    constexpr float WEIGHT_HOOK_DETECTION = 0.8f;
    constexpr float WEIGHT_TIMING_ANOMALY = 0.5f;
    constexpr float WEIGHT_NETWORK_ANOMALY = 0.4f;
    constexpr float WEIGHT_OVERLAY_DETECTION = 0.75f;
    constexpr float WEIGHT_GRAPHICS_HOOK = 0.85f;
    constexpr float WEIGHT_RENDERING_ANOMALY = 0.65f;
    
    // ═══════════════════════════════════════════════════════════
    //                    PERFORMANCE CONSTANTS
    // ═══════════════════════════════════════════════════════════
    
    constexpr DWORD CACHE_TIMEOUT_MS = 30000;
    constexpr size_t ADAPTIVE_THRESHOLD = 5;
    constexpr DWORD STARTUP_GRACE_PERIOD_MS = 15000;
    constexpr DWORD LOADING_DETECTION_DELAY_MS = 10000;
    constexpr DWORD GAME_STATE_CHECK_INTERVAL_MS = 2000;
    constexpr size_t ESCALATION_THRESHOLD = 3;
    constexpr DWORD ACTION_TIMEOUT_MS = 30000;
    
    // ═══════════════════════════════════════════════════════════
    //                    FILE AND LOG CONSTANTS
    // ═══════════════════════════════════════════════════════════
    
    constexpr size_t MAX_LOG_FILE_SIZE_MB = 10;
    constexpr const char* DEFAULT_LOG_FILENAME = "garudahs.log";
    constexpr const char* DEFAULT_CONFIG_FILENAME = "garudahs_config.ini";
    constexpr const char* DEFAULT_DETECTION_RULES_FILENAME = "detection_rules.json";
    constexpr const char* DEFAULT_MESSAGES_FILENAME = "messages.json";

} // namespace Constants
} // namespace GarudaHS
