#ifndef __RAWSOCKET_H__
#define __RWASOCKET_H__

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/ioctl.h>        // macro ioctl is defined
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#include <net/if.h>			  // struct ifreq

#include <errno.h>

#include "message.h"
#include "memory.h"

int createRawSocket (const char *interface);

#endif
