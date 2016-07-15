#ifndef __DNS_H__
#define __DNS_H__

#include <iostream>
#include <ctime>

#include <math.h>
#include <stdexcept>

#include <ldns/ldns.h>

using namespace std;

// exception class for Domain class
class DNSException:public runtime_error {
	public:
		DNSException(const std::string& _message):runtime_error(_message) {}
};


class Domain {
		static const int Ok;
		static const int Error;

                string randHost(int); // generate random host name
        public:
                string name; // domain name
                string lastQueryAddr; // last random used FQDN
                int noQuery; // number of queries
		int noFailed; // number of failed queries
                double deviation; // latency deviation
                double average; // average lateceny
                int lastResponse; // last query latency
                unsigned long long firstTimestamp; // first query timestamp
                unsigned long long  lastTimestamp; // last query timestamp

                Domain(string);
                ~Domain();
                int query(); // DNS query to domain
};

#endif

