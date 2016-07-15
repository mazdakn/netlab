#include "tcp.h"

int tcpDecoder (const u_char *header, int verbosity)
{
	struct tcphdr *tcp_hdr = (struct tcphdr *)(header);

	if (verbosity > 0)
		tcpPrinter (tcp_hdr);

	return 0;
}

void tcpPrinter (const struct tcphdr *tcp_hdr)
{
	fprintf (stdout, " TCP(");
    fprintf(stdout,"%hu", tcp_hdr->th_sport);

    fprintf(stdout,"->%hu", tcp_hdr->th_dport);
	fprintf (stdout,")");
}
