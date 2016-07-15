#include <iostream>
#include <string>

#include "db.hpp"

/* this class controls queries toward mysql db
   exceptions should be handled in main application
   mostly mysqlpp::ConnectionFailed exception
*/


DataBase::DataBase()
{
}

DataBase::~DataBase()
{
	//conn.close(); // close database connection
}

void DataBase::connect(string database, string server, string username, string password)
{
	// connect to db, raise exception on error
	// exception should be handled
	conn.connect(database.c_str(), server.c_str(), username.c_str(), password.c_str());
}

// init data about a domain
void DataBase::init(string name)
{
	// INSERT INTO dns VALUES ("XXXX",0,0,0,0,0,0)
	// exception should be handled
       	mysqlpp::Query query = conn.query("INSERT INTO dns VALUES ('" + name + "',0,0,0,0,0,0)");
       	query.store();
}

// check if information about one domain exist in database
int DataBase::exist(string domain)
{
	// SELECT * from dns WHERE doman="XXXX"
	// in order to not overwrite data in db
        mysqlpp::Query query = conn.query("SELECT *  FROM dns WHERE domain='" + domain + "'");
	mysqlpp::StoreQueryResult res = query.store();
	return (!res.empty());
}

// update data about a domain in database
void DataBase::update(string name, int noQuery, int lastResponse, double average, double deviation, unsigned long long firstTimestamp, unsigned long long lastTimestamp)
{
	stringstream noQueryS; // number of queries
	stringstream lastResponseS; // last latency
	stringstream averageS; // average latency
	stringstream deviationS; // latency deviation
	stringstream firstTimestampS; // first query timestamp
	stringstream lastTimestampS; // last query timestamp

       	mysqlpp::Query query = conn.query();

	// UPDATAE dns SET noQuery,lastResponse,.... WHERE domain="xxxx"
	string q = "UPDATE dns SET noQuery=";
	noQueryS << noQuery;
	q = q + noQueryS.str();
       	q = q + ",lastResponse=";
	lastResponseS << lastResponse;
	q = q + lastResponseS.str();
       	q = q + ",average=";
	averageS << average;
	q = q + averageS.str();
        q = q + ",deviation=";
	deviationS << deviation;
	q = q + deviationS.str();
       	q = q + ",firstTimestamp=";
	firstTimestampS << firstTimestamp;
	q = q + firstTimestampS.str();
        q = q + ",lastTimestamp=";
	lastTimestampS << lastTimestamp;
	q = q + lastTimestampS.str();
       	q = q + " WHERE domain='" + name + "'";

        query << q ;
       	query.store();
}
