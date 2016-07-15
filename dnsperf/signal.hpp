#ifndef __SIGNALHANDLER_H__
#define __SIGNALHANDLER_H_

#include <stdexcept>
#include <signal.h>
#include <errno.h>

#include <iostream>

using std::runtime_error;

// exception class for signal handling
class SignalException:public runtime_error {
	public:
   		SignalException(const std::string& _message):std::runtime_error(_message) {}
};

class SignalHandler {
    		static bool gotSignal; // signal flag

	public:
		SignalHandler() {}
		~SignalHandler() {}

		static bool gotExitSignal(); // check if signal received
		static void setExitSignal(bool state); // set signal flag

    		void setupSignalHandlers(); // setup signal handler
    		static void exitSignalHandler(int); // signal handler
};

#endif
