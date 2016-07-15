#include "utils.h"

int parseArguments(int argc, char *argv[], struct Arguments* args)
{
	int c;
    
	memset(args, 0, sizeof(struct Arguments));
    
	if (argc == 1) return ERROR;

	while ((c = getopt (argc, argv, "hvi:d:x:t:s:l:p:f:g:")) != -1)
		switch (c) {
			case 'i':
				strncpy(args->interface, optarg, (strlen(optarg) > MAX_IFACENAME) ? MAX_IFACENAME:strlen(optarg));
                break;
            case 'd':
				args->driver = atoi(optarg);
                break;
            case 'x':
				args->dumpPkt = atoi(optarg);
				break;
            case 'v':
				args->verbosity++;
                break;
            case 't':
				strncpy(args->target, optarg, (strlen(optarg) > MAX_TARGETNAME) ? MAX_TARGETNAME : strlen(optarg));
                break;
            case 's':
				strncpy(args->source, optarg, (strlen(optarg) > MAX_ADDRESS) ? MAX_ADDRESS : strlen(optarg));
                break;
            case 'l':
				args->length = atoi(optarg);
                break;
            case 'g':
				strncpy(args->generator, optarg, (strlen(optarg) > MAX_PROTOCOL) ? MAX_PROTOCOL : strlen(optarg));
				break;
			case 'p':
				args->port = atoi(optarg);
				break;
            case 'f':
				args->frequency = atoi(optarg);
                break;
            case 'h':
            case '?':
            default:
				return ERROR;
            }

        return OK;
}

void help (char *name)
{
    fprintf (stderr, "%s -i <interface> -d <driver> -t <target> -s <source address> -f <frequency> -l <length> -p <port> -g <generator> -x <no of octet> -vv -h\n\n", name);
    fprintf (stderr, "\t-i <interface>\tInterface name\n");
    fprintf (stderr, "\t-d <driver>\tDriver name (pcap)\n");
    fprintf (stderr, "\t-t <target>\ttarget name, address or ip\n");
    fprintf (stderr, "\t-s <source>\tSource address\n");
    fprintf (stderr, "\t-f <frequency>\tFrequency of generating packet\n");
    fprintf (stderr, "\t-l <length>\tLength of payload\n");
    fprintf (stderr, "\t-p <port>\tport number\n");
    fprintf (stderr, "\t-g <generator>\tPacket generator (icmp, tcp)\n");
    fprintf (stderr, "\t-x <no. octet>\tDump x octet\n");
    fprintf (stderr, "\t-v \t\tVerbose\n");
    fprintf (stderr, "\t-vv \t\tMore verbose\n");
    fprintf (stderr, "\t-h \t\tHelp\n\n");
}


