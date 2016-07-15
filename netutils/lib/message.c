#include "message.h"

void fatal(const char *message, const char *error)
{
	fprintf (stderr, "[-] %s: %s\n", message, error);
	exit(EXIT_FAILURE);
}

void die(const char *msg)
{
	perror(msg);
	exit (EXIT_FAILURE);
}

void info (const char *message)
{
	fprintf (stdout, "[+] %s\n", message);
}
					
