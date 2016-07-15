// Send an IPv4 ICMP packet via raw socket.
// Stack fills out layer 2 (data link) information (MAC addresses) for us.
// Values set for echo request packet, includes some ICMP data.

#include "main.h"

// TODO: any interface
// TODO: signal handler, CTRL+C

int main (int argc, char **argv)
{
  	struct sockaddr_in *src_ip, *dst_ip;
	struct Arguments args;
	char ipsrc[INET_ADDRSTRLEN];
	char ipdst[INET_ADDRSTRLEN];

	if (parseArguments(argc, argv, &args))
    {
		help(argv[0]);
        exit(EXIT_FAILURE);
    }

	dst_ip = resolve(args.target);
	src_ip = resolve(args.source);

	inet_ntop (AF_INET, &(src_ip->sin_addr), ipsrc, INET_ADDRSTRLEN);
	inet_ntop (AF_INET, &(dst_ip->sin_addr), ipdst, INET_ADDRSTRLEN);

    // ANY interface
    if (args.verbosity > 0) {
		fprintf (stdout, "Device: %s\n", args.interface);
        fprintf (stdout, "Driver: %d\n", args.driver);
        fprintf (stdout, "Target: %s (%s)\n", args.target, ipdst);
        fprintf (stdout, "Source: %s (%s)\n", args.source, ipsrc);
        fprintf (stdout, "Payload: %d\n", args.length);
        fprintf (stdout, "Frequenct: %d\n", args.frequency);
    }

    //if (geteuid() != 0)
    //        fatal ("Interface error", "access not permitted");

	setupSignal();

	// check in a better way
	if (strncmp(args.generator, "icmp", 4) == 0)
		return (genloop(&args));
	else
		return (loopTCP(&args, initTCP(&args)));

	return 0;
}

