#pragma once
#include <string>

class ClientSocket {
public:
    static void SendMessageToServer(const std::string& message);
};