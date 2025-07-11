#pragma once
#include <mutex>
#include <memory>
#include <Windows.h>

namespace GarudaHS {
namespace Utils {

    // ═══════════════════════════════════════════════════════════
    //                    RAII HANDLE GUARD
    // ═══════════════════════════════════════════════════════════
    
    class HandleGuard {
    private:
        HANDLE m_handle;
        bool m_shouldClose;
        
    public:
        explicit HandleGuard(HANDLE handle, bool shouldClose = true) 
            : m_handle(handle), m_shouldClose(shouldClose) {}
            
        ~HandleGuard() {
            if (m_shouldClose && m_handle && m_handle != INVALID_HANDLE_VALUE) {
                CloseHandle(m_handle);
            }
        }
        
        // Non-copyable
        HandleGuard(const HandleGuard&) = delete;
        HandleGuard& operator=(const HandleGuard&) = delete;
        
        // Movable
        HandleGuard(HandleGuard&& other) noexcept 
            : m_handle(other.m_handle), m_shouldClose(other.m_shouldClose) {
            other.m_handle = nullptr;
            other.m_shouldClose = false;
        }
        
        HandleGuard& operator=(HandleGuard&& other) noexcept {
            if (this != &other) {
                if (m_shouldClose && m_handle && m_handle != INVALID_HANDLE_VALUE) {
                    CloseHandle(m_handle);
                }
                m_handle = other.m_handle;
                m_shouldClose = other.m_shouldClose;
                other.m_handle = nullptr;
                other.m_shouldClose = false;
            }
            return *this;
        }
        
        HANDLE get() const { return m_handle; }
        operator HANDLE() const { return m_handle; }
        bool isValid() const { return m_handle && m_handle != INVALID_HANDLE_VALUE; }
        
        HANDLE release() {
            m_shouldClose = false;
            return m_handle;
        }
    };

    // ═══════════════════════════════════════════════════════════
    //                    ORDERED LOCK GUARD
    // ═══════════════════════════════════════════════════════════
    
    template<typename Mutex1, typename Mutex2>
    class OrderedLockGuard {
    private:
        std::unique_lock<Mutex1> m_lock1;
        std::unique_lock<Mutex2> m_lock2;
        
    public:
        OrderedLockGuard(Mutex1& mutex1, Mutex2& mutex2) {
            // Always lock in consistent order to prevent deadlock
            if (&mutex1 < &mutex2) {
                m_lock1 = std::unique_lock<Mutex1>(mutex1);
                m_lock2 = std::unique_lock<Mutex2>(mutex2);
            } else {
                m_lock2 = std::unique_lock<Mutex2>(mutex2);
                m_lock1 = std::unique_lock<Mutex1>(mutex1);
            }
        }
        
        // Non-copyable, non-movable
        OrderedLockGuard(const OrderedLockGuard&) = delete;
        OrderedLockGuard& operator=(const OrderedLockGuard&) = delete;
        OrderedLockGuard(OrderedLockGuard&&) = delete;
        OrderedLockGuard& operator=(OrderedLockGuard&&) = delete;
    };

    // ═══════════════════════════════════════════════════════════
    //                    SCOPED TIMER
    // ═══════════════════════════════════════════════════════════
    
    class ScopedTimer {
    private:
        LARGE_INTEGER m_start;
        LARGE_INTEGER m_frequency;
        std::function<void(DWORD)> m_callback;
        
    public:
        explicit ScopedTimer(std::function<void(DWORD)> callback = nullptr) 
            : m_callback(callback) {
            QueryPerformanceFrequency(&m_frequency);
            QueryPerformanceCounter(&m_start);
        }
        
        ~ScopedTimer() {
            if (m_callback) {
                LARGE_INTEGER end;
                QueryPerformanceCounter(&end);
                DWORD elapsedMs = static_cast<DWORD>((end.QuadPart - m_start.QuadPart) * 1000 / m_frequency.QuadPart);
                m_callback(elapsedMs);
            }
        }
        
        DWORD getElapsedMs() const {
            LARGE_INTEGER end;
            QueryPerformanceCounter(&end);
            return static_cast<DWORD>((end.QuadPart - m_start.QuadPart) * 1000 / m_frequency.QuadPart);
        }
    };

    // ═══════════════════════════════════════════════════════════
    //                    THREAD SAFE COUNTER
    // ═══════════════════════════════════════════════════════════
    
    class ThreadSafeCounter {
    private:
        mutable std::mutex m_mutex;
        size_t m_count;
        
    public:
        ThreadSafeCounter() : m_count(0) {}
        
        void increment() {
            std::lock_guard<std::mutex> lock(m_mutex);
            ++m_count;
        }
        
        void decrement() {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_count > 0) --m_count;
        }
        
        size_t get() const {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_count;
        }
        
        void reset() {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_count = 0;
        }
        
        size_t exchange(size_t newValue) {
            std::lock_guard<std::mutex> lock(m_mutex);
            size_t oldValue = m_count;
            m_count = newValue;
            return oldValue;
        }
    };

    // ═══════════════════════════════════════════════════════════
    //                    SAFE BUFFER
    // ═══════════════════════════════════════════════════════════
    
    template<size_t Size>
    class SafeBuffer {
    private:
        char m_buffer[Size];
        
    public:
        SafeBuffer() {
            ZeroMemory(m_buffer, Size);
        }
        
        char* data() { return m_buffer; }
        const char* data() const { return m_buffer; }
        constexpr size_t size() const { return Size; }
        constexpr size_t capacity() const { return Size - 1; } // Reserve space for null terminator
        
        bool copyFrom(const char* source, size_t maxLength = Size - 1) {
            if (!source) return false;
            
            size_t copyLength = strnlen_s(source, maxLength);
            if (copyLength >= Size) return false;
            
            ZeroMemory(m_buffer, Size);
            memcpy_s(m_buffer, Size, source, copyLength);
            m_buffer[copyLength] = '\0';
            return true;
        }
        
        bool copyFrom(const std::string& source) {
            return copyFrom(source.c_str(), source.length());
        }
        
        std::string toString() const {
            return std::string(m_buffer);
        }
        
        void clear() {
            ZeroMemory(m_buffer, Size);
        }
    };

    // ═══════════════════════════════════════════════════════════
    //                    UTILITY FUNCTIONS
    // ═══════════════════════════════════════════════════════════
    
    // Safe string conversion with bounds checking
    inline bool SafeWideToMultiByte(const std::wstring& wide, std::string& result, UINT codePage = CP_UTF8) {
        if (wide.empty()) {
            result.clear();
            return true;
        }
        
        int size = WideCharToMultiByte(codePage, 0, wide.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (size <= 0) return false;
        
        result.resize(size - 1);
        int actualSize = WideCharToMultiByte(codePage, 0, wide.c_str(), -1, &result[0], size, nullptr, nullptr);
        return actualSize > 0;
    }
    
    // Safe process name extraction
    inline std::string SafeGetProcessName(DWORD processId) {
        HandleGuard hSnap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (!hSnap.isValid()) {
            return "";
        }
        
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(PROCESSENTRY32W);
        
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (pe.th32ProcessID == processId) {
                    std::string result;
                    if (SafeWideToMultiByte(pe.szExeFile, result)) {
                        return result;
                    }
                    return "";
                }
            } while (Process32NextW(hSnap, &pe));
        }
        
        return "";
    }
    
    // Safe timing measurement
    inline DWORD SafeMeasureTime(std::function<void()> operation) {
        if (!operation) return 0;
        
        LARGE_INTEGER frequency, start, end;
        if (!QueryPerformanceFrequency(&frequency)) return 0;
        
        QueryPerformanceCounter(&start);
        operation();
        QueryPerformanceCounter(&end);
        
        return static_cast<DWORD>((end.QuadPart - start.QuadPart) * 1000 / frequency.QuadPart);
    }

} // namespace Utils
} // namespace GarudaHS
