#include "signal.hpp"

// signal flag
bool SignalHandler::gotSignal = false;

//check if signal received
bool SignalHandler::gotExitSignal()
{
	return gotSignal;
}

// set signal flag
void SignalHandler::setExitSignal(bool state)
{
	gotSignal = state;
}

// signal handler
void SignalHandler::exitSignalHandler(int signal)
{
    std::cout << "[*] Received CTRL+C. wait for safe exit" << std::endl;
    gotSignal = true;
}

// setup signal handler
void SignalHandler::setupSignalHandlers()
{
    if (signal((int) SIGINT, SignalHandler::exitSignalHandler) == SIG_ERR)
        throw SignalException("Error setting up signal handlers"); //???
}
