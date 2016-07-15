#include "app.hpp"

/* verbosity levels */
const int App::Verbose = 1;
const int App::VeryVerbose = 2;

/* statue code */
const int App::Ok = 0;
const int App::Error = -1;

App::App(int argc, char **argv)
{
	this->argc = argc; 	// CLI argc
	this->argv = argv; 	// CLI argv

	verbosity = 0; 		// verbosity level
	freq = 0; 		// query frequnecy

	server = ""; 		// db server address
	username = ""; 		// db username
	password = ""; 		// db password
	dbname = "network";	// db name

	connected = false;

	/* setup signal handler for CTRL+C */
	try {
		handler.setupSignalHandlers();
	}
        catch (SignalException &e) {
		fatal ("Cannot setup signal handler");
	}
}

App::~App()
{
}

/* parse CLI arguments from argv, and argv
   -v		verbose
   -vv 		very verbose
   -f 		frequency of query
   -s		db server address
   -u 		db username
   -p		db password
   -h 		help */
int App::parseArguments()
{
       int c;

        if (argc == 1) return Error;

        while ((c = getopt (argc, argv, "hvf:s:u:p:")) != -1)
                switch (c) {
                        case 'v':
                                verbosity++;
                                break;
                        case 'f':
                                freq = atoi(optarg);
                                break;
                        case 's':
                                server = optarg;
                                break;
                        case 'u':
                                username = optarg;
                                break;
                        case 'p':
                                password = optarg;
                                break;
                        case 'h':
                        case '?':
                        default:
                                return Error;
        }

        return Ok;
}

/* connect to db */
int App::connectdb()
{
	info ("Connecting to database " + server);

        try {
		db.connect(dbname, server, username, password);
		connected = true;
		return Ok;
	}
	catch (mysqlpp::ConnectionFailed &e) {
		connected = false;
		return (fatal(e.what()));
	}
}

/* add domain to list of domains, domSet */
void App::addDomain(string name)
{
	info ("Added " + name + " to list");
	domSet.push_front(new Domain(name));
}

/* send DNS query to all domain in domSet and update db with stats */
void App::queryAll()
{
        string name;
        int noQuery;
        int lastResponse;
        double average;
        double deviation;
        unsigned long long firstTimestamp;
        unsigned long long lastTimestamp;

        std::list<Domain*>::iterator domIt;

	for (domIt = domSet.begin(); domIt != domSet.end(); domIt++) {

		if (handler.gotExitSignal()) break; // if CTRL+C break

       		info ("Querying " + (*domIt)->name);

		// if query fails
		if ((*domIt)->query()) {
               		info ("Queried " + (*domIt)->lastQueryAddr + " - Failed");
                       	continue;
               	}

		// output about query
               	stringstream tmp;
               	tmp << (*domIt)->lastResponse;
               	info ("Queried " + (*domIt)->lastQueryAddr + " - " + tmp.str() + " ms");

               	name = (*domIt)->name;
               	noQuery = (*domIt)->noQuery;
               	lastResponse = (*domIt)->lastResponse;
               	average = (*domIt)->average;
               	deviation = (*domIt)->deviation;
               	firstTimestamp = (*domIt)->firstTimestamp;
               	lastTimestamp = (*domIt)->lastTimestamp;

		// update db with stats
		if (connected) {
               		info ("Updating db for " + (*domIt)->name);
			if (!db.exist((*domIt)->name)) db.init((*domIt)->name);
               		db.update(name, noQuery, lastResponse, average, deviation, firstTimestamp, lastTimestamp);
		}
	}
}

/* main app loop, calls queryAll and show results, and wait for next round */
int App::qloop()
{
	while (!handler.gotExitSignal()) { 			// do until CTRL+C is hit
		try {
			if (!connected) connectdb();		// if not connected, connect to db

			queryAll(); 				// query all domains
                	showResult();	 			// show results if -vv

                	// Exit if Ctrl+C received during query
                	if (handler.gotExitSignal()) break; 	// if CTRL+C hit break

                	info ("Waiting for next round");
                	sleep(freq); 				// wait for next period
     		}
		catch (mysqlpp::ConnectionFailed &e) { // if connections fails
			connected = false;
			fatal(e.what());
		}
		catch (mysqlpp::BadQuery &e) {
			connected = false;
			fatal(e.what());
		}
		catch (DNSException& e) { // ldns errors happen
			fatal(e.what());
		}
		catch (exception& e) {
			return (fatal(e.what()));
		}
	}

	return Ok;
}

/* show query results */
void App::showResult()
{
        if (verbosity < VeryVerbose)
                return;

        std::list<Domain*>::iterator domIt;

        cout << "[+] Result for query " << endl << endl;

        cout << setw(15) << left << "Domain";
        cout << "\tNo.\tFailed\tLast\tAve.\tDev.\tFirst Timestamp\tLast Timestamp" << endl;
        cout << "_________________________________________________________________________________________";
        cout << endl;

        for (domIt = domSet.begin(); domIt != domSet.end(); domIt++) {
                cout << setw(15) << left << (*domIt)->name << "\t";
                cout << (*domIt)->noQuery << "\t";
                cout << (*domIt)->noFailed << "\t";
                cout << (*domIt)->lastResponse << "\t";
                cout << (*domIt)->average << "\t";
                cout << (*domIt)->deviation << "\t";
                cout << (*domIt)->firstTimestamp << "\t" ;
                cout << (*domIt)->lastTimestamp << endl ;
        }
        cout << endl;
}

/* ouput information in verbosity level 1 */
void App::info (string message)
{
	if (verbosity >= Verbose)
		cout << "[+] " << message << endl;
}

/* output error to cerr */
int App::fatal (string message)
{
	cerr << "[-] " << message << endl;
	return Error;
}

/* app help menu! */
void App::help()
{
        cout <<  argv[0] << " -h -v -f <frequency> -s <server address> -u <username> -p <password> " << endl;
        cout <<  "    -f <frequency>    Query frequency in seconds" << endl;
        cout <<  "    -s                        MySQL server address" << endl;
        cout <<  "    -u                        MySQL username" << endl;
        cout <<  "    -p                        MySQL password" << endl;
        cout <<  "    -v                        Verbose" << endl;
        cout <<  "    -vv                       More verbose" << endl;
        cout <<  "    -h                        Help" << endl << endl;
}
