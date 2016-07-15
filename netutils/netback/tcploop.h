#ifndef __TCPLOOP_H__
#define __TCPLOOP_H__


#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>

#include <string.h>

#include "utils.h"
#include "netutils.h"
#include "tcpsocket.h"
#include "signalhandler.h"


int tcploop(const int);



#endif
