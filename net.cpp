#include "pch.h"
#include "dns.h"
#include "net.h"
#include <chrono>

static int msSince(std::chrono::steady_clock::time_point t0) {
	using namespace std::chrono;
	return (int)duration_cast<milliseconds>(steady_clock::now() - t0).count();
}

bool sendQ(const char* srv, const char* pkt, int size, char* rsp, int& len) {
	SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == INVALID_SOCKET) {
		printf("socket() error %d\n", WSAGetLastError());
		return false;
	}

	// OS picks local port
	sockaddr_in locat;
	memset(&locat, 0, sizeof(locat));

	locat.sin_family = AF_INET;
	locat.sin_addr.s_addr = INADDR_ANY;
	locat.sin_port = htons(0);
	
	if (bind(sock, (sockaddr*)&locat, sizeof(locat)) == SOCKET_ERROR) {
		printf("bind() error %d\n", WSAGetLastError());
		closesocket(sock);
		return false;
	}

	// DNS server address
	sockaddr_in rem;
	memset(&rem, 0, sizeof(rem));

	rem.sin_family = AF_INET;
	rem.sin_addr.s_addr = inet_addr(srv);
	rem.sin_port = htons(53);

	if (rem.sin_addr.s_addr == INADDR_NONE) {
		printf("invalid server IP: %s\n", srv);
		closesocket(sock);
		return false;
	}

	int res = 0;
	for (int att = 0; att < MAX_ATTEMPTS && res == 0; att++) {
		printf("Attempt %d with %d bytes... ", att, size);
		auto t0 = std::chrono::steady_clock::now();

		if (sendto(sock, pkt, size, 0, (sockaddr*)&rem, sizeof(rem)) == SOCKET_ERROR) {
			printf("socket error %d\n", WSAGetLastError());
			res = -1;
			break;
		}

		fd_set fds;
		FD_ZERO(&fds);
		FD_SET(sock, &fds);

		timeval tv;
		tv.tv_sec = 10;
		tv.tv_usec = 0;

		int ready = select(0, &fds, NULL, NULL, &tv);
		if (ready == SOCKET_ERROR) {
			printf("socket error %d\n", WSAGetLastError());
			res = -1;
		} else if (ready == 0) {
			printf("timeout in %d ms\n", msSince(t0)); // retries loop after timeout
		} else {
			sockaddr_in from;
			int fl = sizeof(from);
			int got = recvfrom(sock, rsp, MAX_DNS_SIZE, 0, (sockaddr*)&from, &fl);

			if (got == SOCKET_ERROR) {
				printf("socket error %d\n", WSAGetLastError()); // oversized packets
				res = -1;
			} else {
				len = got;
				printf("response in %d ms with %d bytes\n", msSince(t0), got);

				if (from.sin_addr.s_addr != rem.sin_addr.s_addr || from.sin_port != rem.sin_port) {
					printf(" ++ invalid reply: wrong sender IP/port\n");
					res = -1;
				} else res = 1;
			}
		}
	}
	// finish the socket and return proper res value
	closesocket(sock);
	return res == 1;
}

