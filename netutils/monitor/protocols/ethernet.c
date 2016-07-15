#include "ethernet.h"

int ethernetDecoder(const u_char *header, int verbosity)
{
	struct ether_header *ether_hdr = (struct ether_header *)(header);

	if (verbosity > 0)
		ethernetPrinter (ether_hdr);

    if (ether_hdr->ether_type && ETHERTYPE_IP)
		ipDecoder (header + 14, verbosity);

	return 0;
}

void ethernetPrinter (struct ether_header *ether_hdr)
{
	int i;

	fprintf (stdout, "Ether(");

	for (i = 0; i < ETH_ALEN - 1; i++)
		if (ether_hdr->ether_shost[i] < 16)
			fprintf (stdout, "0%x:", ether_hdr->ether_shost[i]);
		else
			fprintf (stdout, "%x:", ether_hdr->ether_shost[i]);


	if (ether_hdr->ether_shost[i] < 16)
		fprintf (stdout, "0%x", ether_hdr->ether_shost[ETH_ALEN - 1]);
	else
		fprintf (stdout, "%x", ether_hdr->ether_shost[ETH_ALEN - 1]);

	fprintf (stdout, " -> ");

	for (i = 0; i < ETH_ALEN - 1; i++)
		if (ether_hdr->ether_dhost[i] < 16)
			fprintf (stdout, "0%x:", ether_hdr->ether_dhost[i]);
		else
			fprintf (stdout, "%x:", ether_hdr->ether_dhost[i]);

	if (ether_hdr->ether_dhost[i] < 16)
		fprintf (stdout, "0%x", ether_hdr->ether_dhost[ETH_ALEN - 1]);
	else
		fprintf (stdout, "%x", ether_hdr->ether_dhost[ETH_ALEN - 1]);

	fprintf (stdout, ")");
}
