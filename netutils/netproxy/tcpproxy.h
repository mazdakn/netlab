#ifndef __TCPPROXY_H__
#define __TCPPROXY_H__


#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <errno.h>

#include <string.h>

#include "netutils.h"
#include "utils.h"
#include "tcpsocket.h"
#include "signalhandler.h"

int init (const int port);
int tcpproxy (const struct Arguments *args);

#endif
