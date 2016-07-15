#ifndef __APP_HPP__
#define __APP_HPP__

#include "dns.hpp"
#include "db.hpp"
#include "signal.hpp"

#include <iostream>
#include <list>
#include <iomanip>

using namespace std;

class App {
		static const int Ok;
		static const int Error;

		/* verbosity levels */
		static const int Verbose;
		static const int VeryVerbose;

		std::list<Domain*> domSet;	// list of domains
		DataBase db;			// db instance

		string dbname;
		string server;			// db server address
		string username;		// db username
		string password;		// db password

		bool connected;			// is db connected?

		int verbosity;			// verbosity level
		int freq;			// query frequency

		int argc;			// app argc
		char **argv;			// app argv

		SignalHandler handler;		// signal handler, CTRL+C
	public:
		App(int argc, char **argv);
		~App();

		int parseArguments();		// parse CLI arguments
		int connectdb();		// connect to db

		void addDomain(string);		// add domain to domSet
		void queryAll();		// query all domains
		int qloop();			// loop to query domains and update db

		void info(string);		// output info about app execution:Verbosity 1
		int fatal (string);		// output error to cerr:Verbosity 2

		void help();			// show app help
		void showResult();		// show query results
};

#endif
