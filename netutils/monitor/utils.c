#include "utils.h"

int parseArguments(int argc, char *argv[], struct Arguments* args)
{
    int c;

    memset(args, 0, sizeof(struct Arguments));

    if (argc == 1) return ERROR;
    while ((c = getopt (argc, argv, "hvi:d:f:x:")) != -1)
		switch (c) {
			case 'i':
				strncpy(args->interface, optarg, (strlen(optarg) > MAX_IFACENAME) ? MAX_IFACENAME:strlen(optarg));
                break;
            case 'd':
				args->driver = atoi(optarg);
                break;
            case 'f':
				strncpy(args->filter, optarg, (strlen(optarg) > MAX_FILTERSIZE) ? MAX_FILTERSIZE : strlen(optarg));
                break;
            case 'x':
				args->dumpPkt = atoi(optarg);
                break;
            case 'v':
				args->verbosity++;
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
   fprintf (stderr, "%s -i <interface> -f <filter> -x <no. of octets> -vv\n\n", name);
   fprintf (stderr, "\t-i <interface>\tInterface name\n");
   fprintf (stderr, "\t-f <filter>\tFilter string\n");
   fprintf (stderr, "\t-x <no. octets>\tDump x octets\n");
   fprintf (stderr, "\t-v \t\tVerbose\n");
   fprintf (stderr, "\t-vv \t\tMore verbose\n");
   fprintf (stderr, "\t-h \t\tHelp\n\n");
}

