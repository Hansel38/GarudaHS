#pragma once
#include <string>

class ClientSocket {
public:
    static void Initialize();
    static void SendMessageToServer(const std::string& message);
};