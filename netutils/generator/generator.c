#include "generator.h"

int genloop(struct Arguments *args)
{
	int sock;
        uint8_t *packet;
	int size;
        struct sockaddr_in *src_ip, *dst_ip;
        char ipdst[INET_ADDRSTRLEN];


        packet = allocate_ustrmem (IP_MAXPACKET);

        dst_ip = resolve(args->target);
        src_ip = resolve(args->source);

        inet_ntop (AF_INET, &(dst_ip->sin_addr), ipdst, INET_ADDRSTRLEN);

        size = icmpEncoder(packet, src_ip, dst_ip, args->length );
        sock = createRawSocket (args->interface);


	while (checkSignal())
	{
		if (sendto (sock, packet, size, 0, (struct sockaddr *)dst_ip, sizeof (struct sockaddr)) < 0)
 	               fatal ("sendto failed", strerror(errno));

		fprintf (stdout, "Sent ICMP echo request to %s\n",ipdst);
		fflush (stdout);

		if (args->verbosity > 1)
			dumpPacket (packet, size);

		sleep (args->frequency);

	}

        close (sock);
        free (packet);

	return 0;

}

