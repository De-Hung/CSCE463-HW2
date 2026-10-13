#include "pch.h"
#include "dns.h"
#include "parser.h"

// Reads name starting at off
// Returns NULL on success, else ++ message
static const char* rdName (const unsigned char* b, int len, int off, std::string& out, int& nxt) {
	out.clear();
	nxt = -1;
	int pos = off, jump = 0;

	while (true) {
		if (pos >= len) return "++\tinvalid record: truncated name";
		unsigned char c = b[pos];

		if (c == 0) { // end of name
			if (nxt < 0) nxt = pos + 1;
			return NULL;
		}

		if ((c & 0xC0) == 0xC0) { // compression jump
			if (pos + 1 >= len) return "++\tinvalid record: truncated jump offset";
			
			int tgt = ((c & 0x3F) << 8) | b[pos + 1];
			if (nxt < 0) nxt = pos + 2;
			if (tgt >= len) return "++\tinvalid record: jump beyond packet boundary";
			if (tgt < (int)sizeof(FixedDNSheader)) return "++\tinvalid record: jump into fixed DNS header";
			if (++jump > len) return "++\tinvalid record: jump loop";
			
			pos = tgt;
			continue;
		}

		if (c & 0xC0) return "++\tinvalid record: bad label type";
		if (pos + 1 + c > len) return "++\tinvalid record: truncated name";
		if (!out.empty()) out += '.';

		out.append((const char*)b + pos + 1, c);
		pos += (1 + c);
	}
}

static const char* tName(int t) {
	switch (t) {
		case DNS_A: return "A";
		case DNS_NS: return "NS";
		case DNS_CNAME: return "CNAME";
		case DNS_PTR: return "PTR";
		default: return "?";
	}
}

// Parses records of one section starting at off. Returns false on ++ error.
static bool prsSec(const unsigned char* b, int len, int& off, int cnt, const char* ttl, bool isQ) {
	printf("%s\n", ttl);

	for (int i = 0; i < cnt; i++) {
		if (off >= len) {
			printf("++\tinvalid section: not enough records\n");
			return false;
		}

		std::string nm;
		int next;
		if (const char* e = rdName(b, len, off, nm, next)) {
			printf("\t%s\n", e);
			return false;
		}
		off = next;

		if (isQ) {
			if (off + (int)sizeof(QueryHeader) > len) {
				printf("++\tinvalid record: truncated question header\n");
				return false;
			}

			const QueryHeader* qh = (const QueryHeader*)(b + off);
			printf("\t%s type %d class %d\n", nm.c_str(), ntohs(qh->qType), ntohs(qh->qClass));
			off += sizeof(QueryHeader);
			continue;
		}

		if (off + (int)sizeof(DNSanswerHdr) > len) {
			printf("++\tinvalid record: truncated RR answer header\n");
			return false;
		}

		const DNSanswerHdr* ah = (const DNSanswerHdr*)(b + off);
		int typ = ntohs(ah->type);
		unsigned ttlv = ntohl(ah->TTL);
		int rl = ntohs(ah->len);
		off += sizeof(DNSanswerHdr);

		if (off + rl > len) {
			printf("++\tinvalid record: RR value length stretches the answer beyond packet\n");
			return false;
		}

		if (typ == DNS_A && rl == 4) {
			printf("\t%s A %d.%d.%d.%d TTL = %u\n", nm.c_str(), b[off], b[off + 1], b[off + 2], b[off + 3], ttlv);
		} else if (typ == DNS_NS || typ == DNS_CNAME || typ == DNS_PTR) {
			std::string val;
			int n2;

			if (const char* e = rdName(b, len, off, val, n2)) {
				printf("\t%s\n", e);
				return false;
			}

			printf("\t%s %s %s TTL = %u\n", nm.c_str(), tName(typ), val.c_str(), ttlv);
		}
		off += rl;
	}
	return true;
}

void prsR(const char* rsp, int len, USHORT txid) {
	if (len < (int)sizeof(FixedDNSheader)) {
		printf("++\tinvalid reply: packet smaller than fixed DNS header\n");
		return;
	}

	const unsigned char* b = (const unsigned char*)rsp;
	const FixedDNSheader* fdh = (const FixedDNSheader*)rsp;

	int id = ntohs(fdh->ID);
	int flag = ntohs(fdh->flags);
	int nq = ntohs(fdh->questions);
	int nan = ntohs(fdh->answers);
	int nau = ntohs(fdh->authority);
	int nad = ntohs(fdh->additional);

	printf("  TXID 0x%.4X, flags 0x%.4X, questions %d, answers %d, authority %d, additional %d\n", id, flag, nq, nan, nau, nad);

	if (id != txid) {
		printf("++\tinvalid reply : TXID mismatch, sent 0x % .4X, received 0x % .4X\n", txid, id);
		return;
	}

	int rc = flag & 0xF;
	if (rc != DNS_OK) {
		printf("  failed with Rcode = %d\n", rc);
		return;
	}
	printf("  succeeded with Rcode = %d\n", rc);
	int off = sizeof(FixedDNSheader);

	if (!prsSec(b, len, off, nq, "  ------------ [questions] ----------", true))  return;
	if (!prsSec(b, len, off, nan, "  ------------ [answers] ------------", false)) return;
	if (!prsSec(b, len, off, nau, "  ------------ [authority] ----------", false)) return;
	
	prsSec(b, len, off, nad, "  ------------ [additional] ---------", false);
}