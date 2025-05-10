#pragma once
#include <string>

bool sendCheatReport(const std::string& message, const std::string& server_ip = "127.0.0.1", unsigned short port = 1337);
