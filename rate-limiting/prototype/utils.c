#include "utils.h"

// Pars user input arguments
int parseArguments(int argc, char **argv, struct Arguments* args)
{
    char c;
	uint8_t min; // 

	memset (args, 0, sizeof(struct Arguments)); // zero all fields of args

	// set default values for port, number of packets, and bit rate
	args->port = DEFAULT_PORT; 
	args->packets = DEFAULT_PACKETS;
	args->speed = DEFAULT_SPEED;

	// parse arguments with getopt
    while ((c = getopt (argc, argv, "ha:p:n:s:")) != -1)
        switch (c) {
            case 'a': // -a address
				min = strlen(optarg) > INET_ADDRSTRLEN ? INET_ADDRSTRLEN:strlen(optarg);
                strncpy (args->address, optarg,min);
				args->address[min]='\0';
				break;
            case 'p': // -p port
				if (checkNumber(optarg)) error ("Invalid port number");
				args->port = atoi(optarg);
                break;
            case 'n': // -n number of packets
                if (checkNumber(optarg)) error ("Invalid number of packets");
				args->packets = atoi(optarg);
                break;
            case 's': // -s bit rate
                if (checkNumber(optarg)) error ("Invalid bit rate");
				args->speed = atoi(optarg);
                break;
            case 'h': // -h help
			default:
				help(argv[0]);
                return ERROR;
        }

    return OK;
}

// help funtion. print arguments info
void help (const char *appname)
{
    fprintf (stderr, "%s -a <address> -p <port> -n <packets> -s <speed>\n\n", appname);
    fprintf (stderr, "\t-a <address>\tServer address\n");
    fprintf (stderr, "\t-p <port>\tServer port\n");
    fprintf (stderr, "\t-n <packets>\tNumber of packets\n");
    fprintf (stderr, "\t-s <speed>\tTransmission speed\n");
    fprintf (stderr, "\t-h \t\tHelp\n\n");
}

int checkNumber(const char *number)
{
	for (int i=0; i < strlen(number); i++)
		if (!isdigit(number[i])) return ERROR;

	return OK;
}


// cirital situation: show error message, and exit
void fatal (const char *message)
{
	perror (message);
	exit (EXIT_FAILURE);
}

void error (const char *message)
{
	fprintf (stderr, "%s\n", message);
	exit (EXIT_FAILURE);
}

// show information on stdout
void info (const char *message)
{
	fprintf (stdout, "%s\n", message);
}


