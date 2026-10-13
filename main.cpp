#include "pch.h"
#include "dns.h"
#include "query.h"

int main (int argc, char** argv) {
    if (argc != 3) {
        printf("Usage: %s <hostname or IP> <DNS server IP>\n", argv[0]);
        return 1;
    }

    const char* lookup = argv[1];
    const char* server = argv[2];

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("WSAStartup error %d\n", WSAGetLastError());
        return 1;
    }

    // IP -> PTR query on revIP, else hostname = query
    bool isIP = (inet_addr(lookup) != INADDR_NONE);
    USHORT type = isIP ? DNS_PTR : DNS_A;
    std::string query = isIP ? revIP(lookup) : std::string(lookup);
    USHORT txID = (USHORT)(GetTickCount() & 0xFFFF); // transaction ID

    printf("Lookup  : %s\n", lookup);
    printf("Query : %s, type %d, TXID 0x%.4X\n", query.c_str(),type,txID);
    printf("Server  : %s\n", server);
    printf("********************************\n");

    // create packet
    int size = (int)sizeof(FixedDNSheader) + (int)query.size() + 2 + (int)sizeof(QueryHeader);
    char* packet = new char[size];

    FixedDNSheader* fdh = (FixedDNSheader*)packet;
    QueryHeader* qh = (QueryHeader*)(packet + size - sizeof(QueryHeader));

    fdh->ID = htons(txID);
    fdh->flags = htons(DNS_QUERY | DNS_RD | DNS_STDQUERY);
    fdh->questions = htons(1);
    fdh->answers = fdh->authority = fdh->additional = 0;

    buildQ((char*)(fdh + 1), query.c_str());

    qh->qType = htons(type);
    qh->qClass = htons(DNS_INET);

    // send then parse
    delete[] packet;
    WSACleanup();
    return 0;
}