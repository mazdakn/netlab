#include "signalhandler.h"

static int signalRecieved = 1;

void setupSignal ()
{
	if (signal(SIGINT, signalHandler) == SIG_ERR)
		fatal ("Setting signal handler", strerror(errno));
}

void signalHandler (int signo)
{
	if (signo == SIGINT) {
		signalRecieved = 0;
		info ("ctrl+c pressed");
	}

}

int checkSignal()
{
	return signalRecieved;
}
