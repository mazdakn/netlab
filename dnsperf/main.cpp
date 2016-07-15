#include "app.hpp"

#include <iostream>
#include <string>
#include <list>

int main(int argc, char *argv[])
{
	// create an instance of app class to monitor performance of DNS servers
	App app(argc, argv);

	// parse command line arguments
	if (app.parseArguments()) {
		app.help();
		exit(EXIT_FAILURE);
	}

	// add domains to be monitored

	app.addDomain("google.com");
	app.addDomain("facebook.com");
	app.addDomain("qq.com");
	app.addDomain("yahoo.com");
	app.addDomain("youtube.com");
	app.addDomain("live.com");
	app.addDomain("msn.com");
	app.addDomain("blogger.com");
	app.addDomain("baidu.com");
	app.addDomain("wikipedia.org");

	app.info ("Starting to query");
	app.info ("Press CTRL+C to stop");

	// start app main loop
	exit(app.qloop()); // execute the main loop
}
