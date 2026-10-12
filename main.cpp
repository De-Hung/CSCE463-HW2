#include "pch.h"
#include "dns.h"

int main(int argc, char** argv)
{
    if (argc != 3) {
        printf("Usage: %s <hostname or IP> <DNS server IP>\n", argv[0]);
        return 1;
    }

    const char* lookup = argv[1];
    const char* server = argv[2];

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup error %d\n", WSAGetLastError());
        return 1;
    }

    // IP address -> PTR query, otherwise hostname -> A query
    USHORT qType = (inet_addr(lookup) != INADDR_NONE) ? DNS_PTR : DNS_A;

    printf("Lookup  : %s\n", lookup);
    // TODO: build query string, print "Query   : ..., type N, TXID 0x%.4X"
    printf("Server  : %s\n", server);
    printf("********************************\n");

    // TODO: send/receive with retransmission, then parse

    WSACleanup();
    return 0;
}