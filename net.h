#pragma once
#include "pch.h"

// Sends packets to srv:53, retries MAX_ATTEMPTS times
// Copies reply into rsp, returns true
bool sendQ(const char* srv, const char* pkt, int size, char* rsp, int& len);