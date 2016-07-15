#include "rawsocket.h"

int createRawSocket (const char *interface)
{
    int sock;
	const int on = 1;
	struct ifreq ifr;

	//TODO: better error handling
	if ((sock = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
		fatal ("socket ",strerror(errno));

	memset (&ifr, 0, sizeof (ifr));
	snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
	if (ioctl (sock, SIOCGIFINDEX, &ifr) < 0)
		fatal ("ioctl failed to find interface", strerror(errno));

	if (setsockopt (sock, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof (ifr)) < 0)
		fatal ("setsockopt failed to bind to interface", strerror(errno));
	
	if (setsockopt (sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof (on)) < 0)
		fatal ("setsockopt failed to set IP_HDRINCL", strerror(errno));

	return sock;
}

