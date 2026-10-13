#pragma once
#include "pch.h"

// Parses DNS response
// Prints header, rcode result, four sections
void prsR(const char* rsp, int len, USHORT txid);