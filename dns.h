#pragma once
#include <winsock2.h>

#define MAX_DNS_SIZE 512
#define MAX_ATTEMPTS 3

// query types
#define DNS_A     1
#define DNS_NS    2
#define DNS_CNAME 5
#define DNS_PTR   12
#define DNS_INET  1

// flags
#define DNS_QUERY    (0 << 15)
#define DNS_RESPONSE (1 << 15)
#define DNS_STDQUERY (0 << 11)
#define DNS_AA       (1 << 10)
#define DNS_TC       (1 << 9)
#define DNS_RD       (1 << 8)
#define DNS_RA       (1 << 7)

// rcodes
#define DNS_OK         0
#define DNS_FORMAT     1
#define DNS_SERVERFAIL 2
#define DNS_ERROR      3
#define DNS_NOTIMPL    4
#define DNS_REFUSED    5

#pragma pack(push, 1)
struct FixedDNSheader {
    USHORT ID;
    USHORT flags;
    USHORT questions;
    USHORT answers;
    USHORT authority;
    USHORT additional;
};

struct QueryHeader {
    USHORT qType;
    USHORT qClass;
};

struct DNSanswerHdr {
    USHORT type;
    USHORT qClass;
    UINT   TTL;
    USHORT len;
};
#pragma pack(pop)