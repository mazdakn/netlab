#include "utils.h"

int parseArguments(int argc, char *argv[], struct Arguments* args)
{
    int c;

	memset(args, 0, sizeof(struct Arguments));

	if (argc == 1) return ERROR;

	while ((c = getopt (argc, argv, "hvi:l:s:p:")) != -1)
	
		switch (c) {
			case 'i':
				strncpy(args->interface, optarg, (strlen(optarg) > MAX_IFACENAME) ? MAX_IFACENAME:strlen(optarg));
				break;
			case 'l':
				args->listen = atoi(optarg);
				break;
			case 's':
				strncpy (args->server, optarg, (strlen(optarg) > MAX_SERVER) ? MAX_SERVER : strlen(optarg));
				break;
			case 'p':
				args->port = atoi(optarg);
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
    fprintf (stderr, "%s -i <interface> -p <port> -vv\n\n", name);
	fprintf (stderr, "\t-i <interface>\tInterface name\n");
	fprintf (stderr, "\t-l <port>\tServer port\n");
	fprintf (stderr, "\t-s <server>\tTarget address\n");
	fprintf (stderr, "\t-p <port>\tTarget port\n");
	fprintf (stderr, "\t-v \t\tVerbose\n");
	fprintf (stderr, "\t-vv \t\tMore verbose\n");
	fprintf (stderr, "\t-h \t\tHelp\n\n");
}

