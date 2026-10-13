#include "pch.h"
#include "query.h"

int buildQ(char* out, const char* host) {
	int pos = 0;
	const char* beg = host;
	
	while (true) {
		const char* dot = strchr(beg, '.');
		int len = dot ? (int)(dot - beg) : (int)strlen(beg);
		out[pos++] = (char)len;

		memcpy(out + pos, beg, len);
		
		pos += len;
		if (!dot) break;
		beg = dot + 1;
	}

	// need to add to terminate label
	out[pos++] = 0;
	return pos;
}

std::string revIP(const char* ip) {
	unsigned a,b,c,d;
	sscanf(ip, "%u.%u.%u.%u", &a,&b,&c,&d);
	char res[64];			  // in-adder is domain name idk
	sprintf(res, "%u.%u.%u.%u.in-addr.arpa", d,c,b,a);

	return res;
}