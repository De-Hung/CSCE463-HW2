#pragma once
#include <string>

// turns "www.google.com" into "3www6google3com0"
int buildQ(char* out, const char* host);

// reverse IP address
std::string revIP(const char* ip);
