#include "dns.hpp"

const int Domain::Ok = 0;
const int Domain::Error = -1;

Domain::Domain (string name)
{
	this->name = name;		// domain name
	lastQueryAddr = "";	// random host to query
	noQuery = 0;		// number of queries
	noFailed = 0;		// number of failed queries
	deviation  = 0;		// standard deviation of query time
	average = 0;		// average of query time
	lastResponse = 0;	// latency of last query
	firstTimestamp = 0;	// timestamp of first query
	lastTimestamp = 0;	// timestamp of last query
}

Domain::~Domain()
{
}

/* generate random host name
   to prevent hitting DNS cache */
string Domain::randHost(int length)
{
	int i = 0;
	string str = "";
       	const char charset[] = "0123456789abcdefghijklmnopqrstuvwxyz";

	const size_t max_index = (sizeof(charset) - 1);

	for (i=0; i< length; i++)
		str = str + charset[ rand() % max_index ];

	return str;
}

/* send DNS query to domain
   generate a random host name and resolve it */
int Domain::query()
{
	ldns_rdf *domain = NULL;	// domain resource
       	ldns_pkt *pkt = NULL;		// query packet
        ldns_resolver *res = NULL; 	// DNS resolver

	// create resolver resource
	if (ldns_resolver_new_frm_file(&res, NULL)!=LDNS_STATUS_OK)
		throw DNSException("Cannot create resolver");

	string host = randHost(5) + "." + name ; // generate a random FQDN
 	lastQueryAddr = host;

	// create domain resource for the randomly generated FQDN
	// throw an exception if not possible
	if (!(domain = ldns_dname_new_frm_str(host.c_str())))
		throw DNSException("Cannot create domain object");

	// create and send a query to the randomly generated FQDN
	// return ERROR if failed
	if (!(pkt = ldns_resolver_query(res, domain, LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, LDNS_RD))) {
		noFailed++;
		return Error;
	}

	// calculate stats

	noQuery++;

	// record timestamp
	lastTimestamp = static_cast<unsigned long long> (time(NULL));
 	if (noQuery == 1) firstTimestamp = lastTimestamp;

	// last query latency
	lastResponse = ldns_pkt_querytime(pkt);

	// average response time
	average = (average * (noQuery-1) + lastResponse) / noQuery;

	// deviation
	if (noQuery > 1) {
		deviation = (((noQuery-1) * pow(deviation,2.0))/ noQuery) + (pow(lastResponse - average, 2.0) / (noQuery-1));
		deviation = sqrt(deviation);
	}

	// free packet and domain name resources
        ldns_rdf_deep_free(domain);
	ldns_pkt_free(pkt);
	ldns_resolver_deep_free(res); // free ldns resolver resource

	return Ok;
}
