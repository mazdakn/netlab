#include "icmp.h"

int icmpEncoder (uint8_t *packet, struct sockaddr_in *src_ip, struct sockaddr_in *dst_ip, int length)
{
	uint8_t *data;
	struct icmp icmp_hdr;
	struct ip ip_hdr;
	int *ip_flags;

  	ip_flags = allocate_intmem (4);
        data = allocate_ustrmem (IP_MAXPACKET);

	// IPv4 header
  	ip_hdr.ip_hl = IP4_HDRLEN / sizeof (uint32_t); // number of 32 bit words
  	ip_hdr.ip_v = 4;
  	ip_hdr.ip_tos = 0;

  	// Total length of datagram (16 bits): IP header + ICMP header + ICMP data
  	ip_hdr.ip_len = htons (IP4_HDRLEN + ICMP_HDRLEN + length);
  	ip_hdr.ip_id = htons (0);

  	ip_flags[0] = 0; // zero
  	ip_flags[1] = 0; // do not fragment
  	ip_flags[2] = 0; // more fragmetn
  	ip_flags[3] = 0; // fragmentation offset (13 bits)

	ip_hdr.ip_off = htons ((ip_flags[0] << 15) + (ip_flags[1] << 14) + (ip_flags[2] << 13) +  ip_flags[3]);
  	ip_hdr.ip_ttl = 255; // default to max
  	ip_hdr.ip_p = IPPROTO_ICMP;

	ip_hdr.ip_src = src_ip->sin_addr;
	ip_hdr.ip_dst = dst_ip->sin_addr;

  	ip_hdr.ip_sum = 0; //ipv4 checksum, 0 when calculating
  	ip_hdr.ip_sum = checksum ((uint16_t *) &ip_hdr, IP4_HDRLEN);

	//ICMP header
	icmp_hdr.icmp_type = ICMP_ECHO; // message type
  	icmp_hdr.icmp_code = 0; // message code
  	icmp_hdr.icmp_id = htons (1000); // identifier, usually pid sending process
  	icmp_hdr.icmp_seq = htons (1); // sequence number, start at 0
  	icmp_hdr.icmp_cksum = 0; // checksum, 0 when calculating checksum

	// data
	randomPayload (data, length);

	memcpy (packet, &ip_hdr, IP4_HDRLEN);
 	memcpy ((packet + IP4_HDRLEN), &icmp_hdr, ICMP_HDRLEN);
	memcpy (packet + IP4_HDRLEN + ICMP_HDRLEN, data, length);
	icmp_hdr.icmp_cksum = checksum ((uint16_t *) (packet + IP4_HDRLEN), length + ICMP_HDRLEN);
	memcpy ((packet + IP4_HDRLEN), &icmp_hdr, ICMP_HDRLEN);

  	//free (data); ???
	return length + IP4_HDRLEN + ICMP_HDRLEN;
}


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
