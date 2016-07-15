#include "icmp.h"

int icmpDecoder (const u_char *header, int verbosity)
{
	struct icmphdr *icmp_hdr = (struct icmphdr *)(header);

    if (verbosity > 0)
		icmpPrinter (icmp_hdr);

	return 0;
}

void icmpPrinter (const struct icmphdr *icmp_hdr)
{
    fprintf (stdout, " ICMP(");

	switch (icmp_hdr->type) {

		case ICMP_ECHOREPLY:
			printf ("echo reply");
			break;
		case ICMP_DEST_UNREACH:
			printf ("destination unreachable");
			break;
		case ICMP_SOURCE_QUENCH:
			printf ("source quench");
			break;
		case ICMP_REDIRECT:
			printf ("redirect");
			break;
		case ICMP_ECHO:
			printf ("echo request");
			break;
		case ICMP_TIME_EXCEEDED:
			printf ("time exceeded");
			break;
		default:
			printf ("type %d", icmp_hdr->type);
	}

    fprintf (stdout,")");
}
