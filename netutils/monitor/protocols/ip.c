#include "ip.h"

int ipDecoder (const u_char *header, int verbosity)
{
	struct ip *ip_hdr = (struct ip *)(header);
	int ip_len = (ip_hdr->ip_hl) * 4;

    if (verbosity > 0)
		ipPrinter (ip_hdr);

	switch (ip_hdr->ip_p) {
		case 1:
	                icmpDecoder (header + ip_len, verbosity);
			break;
		case 6:
	                tcpDecoder (header + ip_len, verbosity);
			break;
		case 17:
	                udpDecoder (header + ip_len, verbosity);
			break;
		default:
			fprintf (stdout, " IP(Proto %d)", ip_hdr->ip_p);
	}

	return 0;
}

void ipPrinter (const struct ip *ip_hdr)
{
	fprintf (stdout, " IP(");
    fprintf (stdout, "%s", inet_ntoa(ip_hdr->ip_src));

    fprintf(stdout," -> %s", inet_ntoa(ip_hdr->ip_dst));
    fprintf (stdout,")");
}
