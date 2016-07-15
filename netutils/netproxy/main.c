#include "main.h"

// TODO: any interface

int main(int argc,char *argv[])
{
	struct Arguments args;

	if (parseArguments(argc, argv, &args))
	{
		help(argv[0]);
		exit(EXIT_FAILURE);
	}

	// ANY interface
	if (args.verbosity > 0) {
		fprintf (stdout, "Device: %s\n", args.interface);
		fprintf (stdout, "Port: %d\n", args.port);
	}

	setupSignal();

	tcpproxy (&args);

	exit(EXIT_SUCCESS); // exit normally
}
