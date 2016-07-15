#ifndef __SIGNALHANDLER_H__
#define __SIGNALHANDLER_H__

#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <string.h>

#include "message.h"

void setupSignal ();
void signalHandler (int signo);
int checkSignal();

#endif
