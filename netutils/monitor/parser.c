#include "parser.h"

void pktParser(u_char *user, const struct pcap_pkthdr *header,const u_char *payload)
{
    struct Arguments *args = (struct Arguments *) user;

	time_t stamp = header->ts.tv_sec;
    struct tm ts;
    char buf[80];

	if (!checkSignal())
		exit (EXIT_SUCCESS);

    ts = *localtime(&stamp);
    strftime (buf, sizeof(buf), "%H:%M:%S", &ts);

	if (args->verbosity > 0)
		fprintf (stdout, "%s " , buf);

	// check if there is enough bytes in the captured data
    /*if (header->caplen < 2*TCP_NORMAL_HEADER_LEN+14)
    {
		return -1;
    }*/

	ethernetDecoder(payload, args->verbosity);

    fprintf(stdout, "\n");
    fflush(stdout);

	// check for correct length
	if (args->dumpPkt > 0)
		dumpPacket(payload, args->dumpPkt);
}
