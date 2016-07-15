#include "udp.h"

int udpDecoder (const u_char *header, int verbosity)
{
	struct udphdr *udp_hdr = (struct udphdr *)(header);

    if (verbosity > 0)
		udpPrinter (udp_hdr);

    return 0;
}

void udpPrinter (const struct udphdr *udp_hdr)
{
	fprintf (stdout, " UDP(");
    fprintf (stdout, "%hu", udp_hdr->uh_sport);

    fprintf (stdout, "->%hu", udp_hdr->uh_dport);
	fprintf (stdout, ")");
}

