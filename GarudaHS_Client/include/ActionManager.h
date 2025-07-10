#pragma once

#ifndef ACTIONMANAGER_H
#define ACTIONMANAGER_H

#include <Windows.h>
#include <string>
#include <vector>
#include <queue>
#include <map>
#include <functional>
#include <atomic>
#include <mutex>

namespace GarudaHS {

    enum class ActionType {
        LOG_ONLY = 0,           // Just log the detection
        WARNING = 1,            // Show warning to user
        SUSPEND_PROCESS = 2,    // Suspend the suspicious process
        TERMINATE_PROCESS = 3,  // Terminate the suspicious process
        TERMINATE_GAME = 4,     // Terminate the game
        QUARANTINE = 5,         // Move file to quarantine
        REPORT_SERVER = 6       // Report to server
    };

    enum class ActionPriority {
        LOW = 0,
        NORMAL = 1,
        HIGH = 2,
        CRITICAL = 3
    };

    struct ActionRequest {
        ActionType type;
        ActionPriority priority;
        std::string target;         // Process name, file path, etc.
        std::string reason;         // Why this action is needed
        float confidence;           // Confidence level (0.0-1.0)
        DWORD timestamp;           // When action was requested
        std::map<std::string, std::string> metadata; // Additional data
        bool requiresConfirmation;  // Needs user confirmation
        DWORD timeoutMs;           // Action timeout
    };

    struct ActionResult {
        bool success;
        std::string message;
        DWORD executionTime;
        std::string details;
    };

    /**
     * Manages anti-cheat actions with logging and gradual enforcement
     */
    class ActionManager {
    private:
        std::queue<ActionRequest> m_actionQueue;
        std::vector<ActionRequest> m_pendingActions;
        std::vector<std::pair<ActionRequest, ActionResult>> m_actionHistory;
        
        mutable std::mutex m_queueMutex;
        mutable std::mutex m_historyMutex;
        
        std::atomic<bool> m_enabled;
        std::atomic<bool> m_enforcementMode;
        
        // Configuration
        bool m_requireConfirmationForCritical;
        bool m_enableGradualEscalation;
        DWORD m_actionTimeout;
        DWORD m_maxQueueSize;
        
        // Escalation settings
        std::map<std::string, DWORD> m_violationCounts;
        std::map<ActionType, ActionType> m_escalationMap;
        DWORD m_escalationThreshold;
        
        // Callbacks
        std::function<void(const ActionRequest&)> m_preActionCallback;
        std::function<void(const ActionRequest&, const ActionResult&)> m_postActionCallback;
        std::function<bool(const ActionRequest&)> m_confirmationCallback;
        
        // Statistics
        std::map<ActionType, DWORD> m_actionCounts;
        DWORD m_totalActions;
        DWORD m_successfulActions;
        DWORD m_failedActions;
        
        // Private methods
        ActionResult ExecuteAction(const ActionRequest& request);
        ActionResult LogAction(const ActionRequest& request);
        ActionResult ShowWarning(const ActionRequest& request);
        ActionResult SuspendProcess(const ActionRequest& request);
        ActionResult TerminateProcess(const ActionRequest& request);
        ActionResult TerminateGame(const ActionRequest& request);
        ActionResult QuarantineFile(const ActionRequest& request);
        ActionResult ReportToServer(const ActionRequest& request);
        
        bool ShouldEscalate(const std::string& target);
        ActionType GetEscalatedAction(ActionType originalAction);
        void UpdateViolationCount(const std::string& target);
        bool RequiresConfirmation(const ActionRequest& request);

    public:
        ActionManager();
        ~ActionManager();
        
        // Lifecycle
        bool Initialize();
        void Shutdown();
        
        // Action management
        bool QueueAction(const ActionRequest& request);
        void ProcessQueue();
        void ClearQueue();
        std::vector<ActionRequest> GetPendingActions() const;
        
        // Immediate actions
        ActionResult ExecuteImmediate(const ActionRequest& request);
        ActionResult LogDetection(const std::string& threat, float confidence, const std::string& details = "");
        ActionResult ShowUserWarning(const std::string& message, const std::string& title = "GarudaHS");
        
        // Configuration
        void SetEnforcementMode(bool enabled);
        void SetRequireConfirmation(bool required);
        void SetGradualEscalation(bool enabled);
        void SetActionTimeout(DWORD timeoutMs);
        void SetEscalationThreshold(DWORD threshold);
        
        // Escalation configuration
        void SetEscalationMap(ActionType from, ActionType to);
        void LoadDefaultEscalationMap();
        
        // Callbacks
        void SetPreActionCallback(std::function<void(const ActionRequest&)> callback);
        void SetPostActionCallback(std::function<void(const ActionRequest&, const ActionResult&)> callback);
        void SetConfirmationCallback(std::function<bool(const ActionRequest&)> callback);
        
        // Query methods
        bool IsEnforcementMode() const;
        bool IsEnabled() const;
        DWORD GetQueueSize() const;
        DWORD GetViolationCount(const std::string& target) const;
        
        // Statistics
        std::map<ActionType, DWORD> GetActionCounts() const;
        DWORD GetTotalActions() const;
        DWORD GetSuccessfulActions() const;
        float GetSuccessRate() const;
        void ResetStatistics();
        
        // History
        std::vector<std::pair<ActionRequest, ActionResult>> GetActionHistory(DWORD maxEntries = 100) const;
        void ClearHistory();
        
        // Utility
        static std::string ActionTypeToString(ActionType type);
        static std::string PriorityToString(ActionPriority priority);
        std::string GetStatusReport() const;
        
        // Factory methods for common actions
        static ActionRequest CreateLogAction(const std::string& threat, float confidence, const std::string& details = "");
        static ActionRequest CreateWarningAction(const std::string& message, float confidence);
        static ActionRequest CreateTerminateAction(const std::string& processName, float confidence, const std::string& reason);
    };

    /**
     * Feedback loop manager for continuous improvement
     */
    class FeedbackManager {
    private:
        std::vector<std::pair<ActionRequest, bool>> m_feedbackData; // Action + was it correct
        std::map<std::string, float> m_accuracyByThreat;
        std::map<ActionType, float> m_accuracyByAction;
        
        mutable std::mutex m_feedbackMutex;
        
        // Configuration
        bool m_enableLearning;
        DWORD m_maxFeedbackEntries;
        float m_learningRate;
        
        // Statistics
        DWORD m_totalFeedback;
        DWORD m_positiveFeedback;
        DWORD m_negativeFeedback;

    public:
        FeedbackManager();
        ~FeedbackManager();
        
        // Feedback collection
        void RecordFeedback(const ActionRequest& action, bool wasCorrect);
        void RecordFalsePositive(const ActionRequest& action);
        void RecordTruePositive(const ActionRequest& action);
        
        // Analysis
        float GetAccuracyForThreat(const std::string& threat) const;
        float GetAccuracyForAction(ActionType action) const;
        float GetOverallAccuracy() const;
        
        // Recommendations
        std::vector<std::string> GetImprovementSuggestions() const;
        bool ShouldAdjustThreshold(const std::string& threat) const;
        float GetRecommendedThreshold(const std::string& threat) const;
        
        // Configuration
        void SetLearningEnabled(bool enabled);
        void SetLearningRate(float rate);
        void SetMaxFeedbackEntries(DWORD maxEntries);
        
        // Statistics
        DWORD GetTotalFeedback() const;
        float GetPositiveFeedbackRate() const;
        void ResetFeedback();
        
        // Export/Import
        bool ExportFeedbackData(const std::string& filename) const;
        bool ImportFeedbackData(const std::string& filename);
    };

} // namespace GarudaHS

#endif // ACTIONMANAGER_H
