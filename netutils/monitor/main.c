#include "main.h"

// TODO: any interface

int main(int argc,char *argv[])
{
	char errbuffer[PCAP_ERRBUF_SIZE];
	pcap_t *dev_handler=NULL;
	struct bpf_program filter;

	struct Arguments args;

	if (parseArguments(argc, argv, &args))
	{
		help(argv[0]);
		exit(EXIT_FAILURE);
	}

	// ANY interface
	if (args.verbosity > 0) {
		fprintf (stdout, "Device: %s\n", args.interface);
		fprintf (stdout, "Driver: %d\n", args.driver);
		fprintf (stdout, "Filter: %s\n", args.filter);
	}

	if (geteuid() != 0)
		fatal ("Interface error", "access not permitted");

	setupSignal();
	
	
	if ((dev_handler = pcap_open_live((const char *)&(args.interface), 120, 1, 0, errbuffer))==NULL)
               	fatal ("Couldn't open interface", pcap_geterr(dev_handler));

	if (pcap_compile(dev_handler, &filter, args.filter, 1, 0) != 0)
        	fatal ("Couldn't parse filter", pcap_geterr(dev_handler));

	if (pcap_setfilter(dev_handler, &filter)==-1)
        	fatal ("Couldn't install filter", pcap_geterr(dev_handler));

	switch (pcap_datalink(dev_handler)) //check for L2 encapsulation
	{
		case DLT_EN10MB: // Ethernet
			info ("Data Link type Ethernet");
			break;
		case DLT_C_HDLC: //Cisco HDLC
			info ("Data Link type HDLC");
			break;
		case DLT_LINUX_SLL: // Linux "cooked" capture encapsulation
			info ("Data Link type Linux Cooked");
			break;
		default: // other types
			info ("Unkown Data Link type");
			break;
	}

	pcap_loop(dev_handler, -1, pktParser, (u_char *)&args);

	//free(device);
	pcap_close(dev_handler);

	exit(EXIT_SUCCESS); // exit normally
}
